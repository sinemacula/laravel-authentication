<?php

declare(strict_types=1);

namespace Tests\Unit\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use Tests\Unit\Stubs\InjectableDeviceStub;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubModel;

/**
 * Unit tests for the JwtGuard contextual guard.
 *
 * Exercises bearer-token reading, payload validation, identity
 * hydration, principal and device binding, and the refresh-token
 * exchange path. Uses Orchestra Testbench so `config(...)` and a
 * real Eloquent connection are available for the device-lookup and
 * refresh round-trip tests.
 *
 * `JwtTokenService` is final so it cannot be mocked by Mockery —
 * tests use a real instance and craft hand-rolled tokens via
 * `Firebase\JWT\JWT::encode()` to drive every branch of the guard.
 * Both `Carbon::setTestNow()` and `JWT::$timestamp` are frozen so
 * expiry assertions remain deterministic.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class JwtGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The guard name forwarded to JwtGuard's constructor. */
    private const string GUARD_NAME = 'jwt-test';

    /** @var string Shared secret for the hand-rolled JWT tokens. */
    private const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string HMAC algorithm for the hand-rolled JWT tokens. */
    private const string ALGORITHM = 'HS256';

    /** @var int Access-token TTL in minutes. */
    private const int TTL_MINUTES = 15;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The mocked identity provider collaborator. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The mocked principal resolver collaborator. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface&\Illuminate\Contracts\Events\Dispatcher The mocked event dispatcher collaborator. */
    private MockInterface $events;

    /** @var \Mockery\MockInterface&\Illuminate\Support\Timebox The mocked timebox collaborator. */
    private MockInterface $timebox;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService Real token service used to decode the tokens the guard parses. */
    private JwtTokenService $tokens;

    /** @var \Carbon\Carbon Frozen clock reference shared by the Carbon and JWT test clocks. */
    private Carbon $now;

    /**
     * Define the Testbench environment: an in-memory sqlite connection
     * (so the refresh path can hit a real Eloquent query) and the
     * package config keys the guard reads.
     *
     * @param  \Illuminate\Foundation\Application $app The Testbench application under construction.
     * @return void
     */
    protected function defineEnvironment($app): void
    {
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
     * Build fresh collaborator mocks, freeze the clock, and create the
     * in-memory schema for StubDevice.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->provider = Mockery::mock(IdentityProvider::class);
        $this->resolver = Mockery::mock(PrincipalResolver::class);
        $this->events   = Mockery::mock(Dispatcher::class);
        $this->timebox  = Mockery::mock(Timebox::class);
        $this->tokens   = new JwtTokenService(self::SECRET, self::ALGORITHM, self::TTL_MINUTES);

        // Default: Timebox::call() invokes the callback directly so
        // credential validation paths run deterministically.
        $this->timebox->shouldReceive('call')
            ->byDefault()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox()));

        Schema::create('stub_devices', static function (Blueprint $blueprint): void {

            $blueprint->ulid('id')->primary();
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();
            $blueprint->string('os')->default('');
            $blueprint->string('refresh_key')->default('');
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
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_devices');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A request with no Authorization header returns null from `user()`.
     *
     * @return void
     */
    public function testUserReturnsNullWhenNoBearerTokenPresent(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $this->events->shouldNotReceive('dispatch');
        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * When the token service cannot parse a token (malformed / bad
     * signature / expired), `user()` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenTokenServiceCannotParseToken(): void
    {
        $guard = $this->makeGuard($this->makeRequest('not-a-jwt'));

        $this->events->shouldNotReceive('dispatch');
        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * A token whose claims array lacks `sub` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenSubClaimMissing(): void
    {
        $token = $this->encodeToken(['pid' => 'p-1', 'did' => 'd-1', 'iat' => $this->now->getTimestamp(), 'exp' => $this->now->getTimestamp() + 600]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $this->events->shouldNotReceive('dispatch');
        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * When `retrieveById()` returns null, `user()` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenIdentityNotFound(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturnNull();

        $this->resolver->shouldNotReceive('resolve');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * When `retrieveById()` returns an Authenticatable that is not an
     * Identity, `user()` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenResolvedUserIsNotIdentity(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $nonIdentity = Mockery::mock(Authenticatable::class);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($nonIdentity);

        $this->resolver->shouldNotReceive('resolve');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * When `resolver->resolve()` returns null, `user()` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenResolverProducesNoPrincipal(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = Mockery::mock(Identity::class);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, null)
            ->andReturnNull();

        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * When the resolved principal's `isActive()` returns false, `user()`
     * returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenResolvedPrincipalIsInactive(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnFalse();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * A valid token whose claims include `sub`, `pid`, and `did` results
     * in the guard binding the identity, principal, and device and
     * dispatching `Authenticated`, `PrincipalAssigned`, and
     * `DeviceAuthenticated`.
     *
     * @return void
     */
    public function testUserBindsIdentityPrincipalAndDeviceFromValidToken(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1', 'did' => 'd-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $device = new StubDevice(['id' => 'd-1']);

        $builder = Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->once()
            ->with('d-1')
            ->andReturn($device);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('devices')
            ->once()
            ->andReturn($builder);

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        $resolved = $guard->user();

        self::assertNotNull($resolved);
        self::assertSame($identity, $guard->identity());
        self::assertSame($principal, $guard->principal());
        self::assertSame($device, $guard->device());
        self::assertContains(Authenticated::class, $dispatched);
        self::assertContains(PrincipalAssigned::class, $dispatched);
        self::assertContains(DeviceAuthenticated::class, $dispatched);
    }

    /**
     * When the token's `pid` claim is non-null the resolver is called
     * with that hint as the second argument.
     *
     * @return void
     */
    public function testUserResolvesPrincipalUsingPidHint(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'principal-hint']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'principal-hint')
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertSame($identity, $guard->user());
    }

    /**
     * A valid token with a `did` claim against an identity that does
     * not implement HasDevices still binds identity+principal but
     * leaves the device null.
     *
     * @return void
     */
    public function testUserSkipsDeviceWhenIdentityDoesNotImplementHasDevices(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1', 'did' => 'd-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertNull($guard->device());
        self::assertNotContains(DeviceAuthenticated::class, $dispatched);
    }

    /**
     * When `parseAllowingExpired()` returns null, `refresh()` returns null.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenTokenCannotBeParsed(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->refresh('not-a-jwt'));
    }

    /**
     * A refresh token without a `did` claim returns null.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenDeviceIdMissingFromClaims(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeToken(['rk' => 'plain-key', 'iat' => $this->now->getTimestamp()]);

        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the device lookup returns null, `refresh()` returns null.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenDeviceLookupFails(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeToken([
            'did' => '01HZZZZZZZZZZZZZZZZZZZZZZZ',
            'rk'  => 'plain-key',
            'iat' => $this->now->getTimestamp(),
        ]);

        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the device's stored refresh key does not match the token's
     * `rk` claim, `refresh()` returns null.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenRefreshKeyDoesNotMatch(): void
    {
        $device = new StubDevice();
        $device->forceFill(['refresh_key' => 'stored-key'])->save();

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeToken([
            'did' => $device->id,
            'rk'  => 'tampered-key',
            'iat' => $this->now->getTimestamp(),
        ]);

        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->refresh($token));
    }

    /**
     * When `device->authenticatable` is not an Identity, `refresh()`
     * returns null.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenAuthenticatableRelationIsNotIdentity(): void
    {
        $device = new StubDevice();
        $device->forceFill(['refresh_key' => 'stored-key'])->save();

        $nonIdentity = new StubModel();
        $device->setRelation('authenticatable', $nonIdentity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeToken([
            'did' => $device->id,
            'rk'  => 'stored-key',
            'iat' => $this->now->getTimestamp(),
        ]);

        $this->resolver->shouldNotReceive('resolve');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->refresh($token));
    }

    /**
     * A valid refresh token returns a new access token, dispatches the
     * `Refreshed` event, and binds the identity/principal/device on the
     * guard.
     *
     * @return void
     */
    public function testRefreshIssuesNewAccessTokenAndDispatchesRefreshedEventOnSuccess(): void
    {
        $identity = new StubIdentity();
        $identity->forceFill(['id' => 7]);

        $device = new StubDevice();
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '7',
            'refresh_key'          => 'stored-key',
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $token = $this->encodeToken([
            'did' => $device->id,
            'rk'  => 'stored-key',
            'iat' => $this->now->getTimestamp(),
        ]);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event;
            });

        $accessToken = $guard->refresh($token);

        self::assertNotNull($accessToken);

        $claims = $this->tokens->parse($accessToken);

        self::assertIsArray($claims);
        self::assertSame(7, $claims['sub']);
        self::assertSame('p-1', $claims['pid']);
        self::assertSame($device->id, $claims['did']);

        $refreshed = array_values(array_filter(
            $dispatched,
            static fn (object $event): bool => $event instanceof Refreshed,
        ));

        self::assertCount(1, $refreshed);
        self::assertInstanceOf(Refreshed::class, $refreshed[0]);
        self::assertSame(self::GUARD_NAME, $refreshed[0]->guard);
        self::assertSame($identity, $refreshed[0]->identity);
    }

    /**
     * A valid refresh additionally binds the identity, principal, and
     * device on the guard itself.
     *
     * @return void
     */
    public function testRefreshBindsIdentityPrincipalAndDeviceOnSuccess(): void
    {
        $identity = new StubIdentity();
        $identity->forceFill(['id' => 7]);

        $device = new StubDevice();
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '7',
            'refresh_key'          => 'stored-key',
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $token = $this->encodeToken([
            'did' => $device->id,
            'rk'  => 'stored-key',
            'iat' => $this->now->getTimestamp(),
        ]);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertNotNull($guard->refresh($token));
        self::assertSame($identity, $guard->identity());
        self::assertSame($principal, $guard->principal());
        self::assertSame($device, $guard->device());
    }

    /**
     * Instantiate JwtGuard with the current set of collaborator mocks
     * and the supplied request.
     *
     * @param  \Illuminate\Http\Request $request The request to bind to the guard.
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeGuard(Request $request): JwtGuard
    {
        return new JwtGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            $request,
            $this->timebox,
            $this->tokens,
        );
    }

    /**
     * Build a real Illuminate Request with (or without) a bearer token
     * Authorization header.
     *
     * @param  string|null $token The bearer token value, or null for no header.
     * @return \Illuminate\Http\Request
     */
    private function makeRequest(?string $token): Request
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
     * @param  array<string, mixed> $payload The claims payload to encode.
     * @return string
     */
    private function encodeToken(array $payload): string
    {
        return JWT::encode($payload, self::SECRET, self::ALGORITHM);
    }

    /**
     * Encode an access-token-style JWT with `iat` and `exp` claims
     * baked in so the real `JwtTokenService::parse()` path accepts it.
     *
     * @param  array<string, mixed> $claims Additional claims layered on top of iat/exp.
     * @return string
     */
    private function encodeAccessToken(array $claims): string
    {
        $now = $this->now->getTimestamp();

        return $this->encodeToken(array_merge($claims, [
            'iat' => $now,
            'exp' => $now + (self::TTL_MINUTES * 60),
        ]));
    }

    /**
     * Swap the configured device model to `DeviceFactoryStub`, whose
     * `newQuery()` yields a Builder mock that returns the supplied
     * in-memory device from `find()`. This lets the refresh tests keep
     * their manually preset `authenticatable` relation intact rather
     * than re-fetching from the DB (which would clear the relation).
     *
     * @param  \Tests\Unit\Stubs\StubDevice $device The in-memory device to return from find().
     * @return void
     */
    private function swapDeviceModelToInMemoryInstance(StubDevice $device): void
    {
        $builder = Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->with($device->id)
            ->andReturn($device);
        $builder->shouldReceive('find')
            ->andReturn(null);

        InjectableDeviceStub::$injectedBuilder = $builder;

        config()->set('laravel-authentication.device.model', InjectableDeviceStub::class);
    }
}
