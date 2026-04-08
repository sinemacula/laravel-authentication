<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Claims;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use Tests\Unit\Stubs\InjectableDeviceStub;
use Tests\Unit\Stubs\StubDevice;

/**
 * Shared base case for the JwtGuard split tests.
 *
 * Owns collaborator mocks, the in-memory `stub_devices` schema, the
 * frozen Carbon and JWT clocks, and the helper factories used by
 * every concrete `JwtGuardTest` variant. Subclasses focus on a
 * single behavioural slice of JwtGuard so each derived class stays
 * well below the project's 20-method-per-class threshold (radarlint
 * S1448).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
abstract class JwtGuardTestCase extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The guard name forwarded to JwtGuard's constructor. */
    protected const string GUARD_NAME = 'jwt-test';

    /** @var string Shared secret for the hand-rolled JWT tokens. */
    protected const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string HMAC algorithm for the hand-rolled JWT tokens. */
    protected const string ALGORITHM = 'HS256';

    /** @var int Access-token TTL in minutes. */
    protected const int ACCESS_TTL = 15;

    /** @var int Refresh-token TTL in minutes. */
    protected const int REFRESH_TTL = 60 * 24 * 30;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The mocked identity provider collaborator. */
    protected MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The mocked principal resolver collaborator. */
    protected MockInterface $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher&\Mockery\MockInterface The mocked event dispatcher collaborator. */
    protected MockInterface $events;

    /** @var \Illuminate\Support\Timebox&\Mockery\MockInterface The mocked timebox collaborator. */
    protected MockInterface $timebox;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService Real token service used to decode the tokens the guard parses. */
    protected JwtTokenService $tokens;

    /** @var \Carbon\Carbon Frozen clock reference shared by the Carbon and JWT test clocks. */
    protected Carbon $now;

    /**
     * Build fresh collaborator mocks, freeze the clock, and create the
     * in-memory schema for StubDevice.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->events   = \Mockery::mock(Dispatcher::class);
        $this->timebox  = \Mockery::mock(Timebox::class);
        $this->tokens   = new JwtTokenService(self::SECRET, self::ALGORITHM, self::ACCESS_TTL, self::REFRESH_TTL);

        // Default: Timebox::call() invokes the callback directly so
        // credential validation paths run deterministically.
        $this->timebox->shouldReceive('call')
            ->byDefault()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        Schema::create('stub_devices', static function (Blueprint $blueprint): void {
            $blueprint->ulid('id')->primary();
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();
            $blueprint->string('os')->default('');
            $blueprint->string('refresh_key', 64)->nullable();
            $blueprint->timestamp('revoked_at')->nullable();
            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clocks and drop the in-memory schema.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_devices');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Define the Testbench environment: an in-memory sqlite connection
     * (so the refresh path can hit a real Eloquent query) and the
     * package config keys the guard reads.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('laravel-authentication.device.model', StubDevice::class);
        $config->set('laravel-authentication.device.table', 'stub_devices');
    }

    /**
     * Instantiate JwtGuard with the current set of collaborator mocks
     * and the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    protected function makeGuard(Request $request): JwtGuard
    {
        $app = $this->app;

        assert($app !== null);

        $exchange = new RefreshTokenExchange(
            $this->tokens,
            $app->make(ConnectionResolverInterface::class),
            $this->events,
            $this->resolver,
            self::GUARD_NAME,
        );

        return new JwtGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            $request,
            $this->timebox,
            $this->tokens,
            $exchange,
        );
    }

    /**
     * Build a real Illuminate Request with (or without) a bearer token
     * Authorization header.
     *
     * @param  string|null  $token
     * @return \Illuminate\Http\Request
     */
    protected function makeRequest(?string $token): Request
    {
        $headers = [];

        if ($token !== null) {
            $headers['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        }

        return Request::create('/test', 'GET', [], [], [], $headers);
    }

    /**
     * Encode a raw payload as a JWT using the shared test secret.
     *
     * @param  array<string, mixed>  $payload
     * @return string
     */
    protected function encodeToken(array $payload): string
    {
        return JWT::encode($payload, self::SECRET, self::ALGORITHM);
    }

    /**
     * Encode an access-token-style JWT with `iat`, `exp`, and
     * `typ = access` claims baked in so the real
     * `JwtTokenService::parse(..., TYPE_ACCESS)` path accepts it.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    protected function encodeAccessToken(array $claims): string
    {
        $now = $this->now->getTimestamp();

        return $this->encodeToken(array_merge($claims, [
            'iat' => $now,
            'exp' => $now + (self::ACCESS_TTL * 60),
            'typ' => Claims::TYPE_ACCESS,
        ]));
    }

    /**
     * Encode a refresh-token-style JWT with `iat`, `exp`, and
     * `typ = refresh` claims so the real
     * `JwtTokenService::parse(..., TYPE_REFRESH)` path accepts it.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    protected function encodeRefreshToken(array $claims): string
    {
        $now = $this->now->getTimestamp();

        return $this->encodeToken(array_merge($claims, [
            'iat' => $now,
            'exp' => $now + (self::REFRESH_TTL * 60),
            'typ' => Claims::TYPE_REFRESH,
        ]));
    }

    /**
     * Swap the configured device model to `InjectableDeviceStub`, whose
     * `newQuery()` yields a Builder mock that returns the supplied
     * in-memory device from `find()`. This lets the refresh tests keep
     * their manually preset `authenticatable` relation intact rather
     * than re-fetching from the DB (which would clear the relation).
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @return void
     */
    protected function swapDeviceModelToInMemoryInstance(StubDevice $device): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->with($device->id)
            ->andReturn($device);
        $builder->shouldReceive('find')
            ->andReturn(null);

        InjectableDeviceStub::$injectedBuilder = $builder;

        config()->set('laravel-authentication.device.model', InjectableDeviceStub::class);
    }
}
