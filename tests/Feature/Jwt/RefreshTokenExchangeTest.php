<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;
use Tests\Unit\Stubs\StubBareDevice;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubInjectableDevice;

/**
 * Feature tests for the `RefreshTokenExchange` service that fill in the few
 * branches not covered by the JwtGuardRefreshTest's end-to-end coverage:
 *
 * - invalid `device.model` config -> refresh fails fast with an explicit
 *   configuration exception rather than falling through to `device_unknown`.
 * - resolver throws `UnresolvableIdentityException` -> the exchange catches it
 *   inside `safeResolvePrincipal` and dispatches `principal_unresolved`.
 * - device model outside the explicit `EloquentDevice` boundary is rejected.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(IdentifierCoercion::class)]
final class RefreshTokenExchangeTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Shared JWT secret for the test fixtures. */
    private const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string HMAC algorithm shared with the test fixtures. */
    private const string ALGORITHM = 'HS256';

    /** @var int Access-token TTL minutes. */
    private const int ACCESS_TTL = 15;

    /** @var int Refresh-token TTL minutes. */
    private const int REFRESH_TTL = 60 * 24 * 30;

    /** @var string Guard name forwarded to the exchange constructor. */
    private const string GUARD_NAME = 'jwt-test';

    /** @var \Mockery\MockInterface Resolver mock. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface Dispatcher mock. */
    private MockInterface $events;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private JwtTokenService $tokens;

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /**
     * Build collaborator mocks, freeze the clock, and create the in-memory
     * `stub_devices` schema.
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

        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->events   = \Mockery::mock(Dispatcher::class);
        $this->tokens   = new JwtTokenService(self::SECRET, self::ALGORITHM, self::ACCESS_TTL, self::REFRESH_TTL);

        Schema::create('stub_devices', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
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
     * Release the frozen clock and drop the in-memory schema.
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
     * An empty `authentication.device.model` config is now an explicit
     * configuration error rather than a silent `device_unknown` refresh
     * failure.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExchangeThrowsWhenConfiguredDeviceModelClassIsEmpty(): void
    {
        config()->set('authentication.device.model', '');

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => '01HZZZZZZZZZZZZZZZZZZZZZZZ',
            'jti' => 'rotation-id',
        ]);

        $this->expectException(InvalidDeviceModelConfiguration::class);

        $exchange->exchange($token);
    }

    /**
     * `safeResolvePrincipal` catches an `UnresolvableIdentityException` thrown
     * by the resolver and surfaces `principal_unresolved` rather than letting
     * the exception propagate up to the caller. Pins the catch arm in
     * `safeResolvePrincipal()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExchangeConvertsUnresolvableIdentityExceptionToFailure(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 9]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andThrow(new UnresolvableIdentityException('cannot resolve'));

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::PRINCIPAL_UNRESOLVED
                    && $event->deviceId === $device->id),
            );

        self::assertNull($exchange->exchange($token));
    }

    /**
     * A malformed refresh payload with an empty `jti` is rejected as
     * `token_invalid` and preserves the parseable device id on the emitted
     * failure event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExchangeIncludesDeviceIdWhenRotationIdShapeIsInvalid(): void
    {
        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => 'device-empty-jti',
            'jti' => '',
        ]);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::TOKEN_INVALID
                    && $event->deviceId === 'device-empty-jti'),
            );

        self::assertNull($exchange->exchange($token));
    }

    /**
     * When the refresh token carries a `pid` hint, the exchange must pass that
     * hint into the resolver and reissue follow-up tokens that preserve it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExchangeUsesPidHintWhenRefreshTokenCarriesPrincipalId(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 12]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '12',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->times(3)
            ->andReturn('p-12');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-12')
            ->andReturn($principal);

        $this->events->shouldNotReceive('dispatch');

        $token = $this->encodeRefreshToken([
            'pid' => 'p-12',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $result = $exchange->exchange($token);

        self::assertNotNull($result);
        self::assertSame($identity, $result->identity);
        self::assertSame($principal, $result->principal);

        $claims = $this->tokens->parse($result->tokens->refreshToken, TokenType::REFRESH);

        self::assertIsArray($claims);
        self::assertSame('p-12', $claims[Claims::PRINCIPAL_ID->value]);
    }

    /**
     * Fail-closed: a hinted principal whose identifier stringifies to `null`
     * is treated as unresolved and attributed to the device id carried by the
     * refresh token.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExchangeRejectsHintedPrincipalWhoseIdentifierStringifiesToNull(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 14]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '14',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->once()
            ->andReturn(null);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'pid' => 'p-hinted',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::PRINCIPAL_MISMATCH
                    && $event->deviceId === $device->id),
            );

        self::assertNull($exchange->exchange($token));
    }

    /**
     * The exchange rejects configured device models that implement the generic
     * `Device` contract but do not satisfy the explicit `EloquentDevice`
     * persistence boundary.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExchangeThrowsWhenConfiguredDeviceModelDoesNotImplementEloquentDevice(): void
    {
        config()->set('authentication.device.model', StubBareDevice::class);

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => 'bare-device-1',
            'jti' => 'rotation-id',
        ]);

        $this->expectException(InvalidDeviceModelConfiguration::class);
        $this->expectExceptionMessage(StubBareDevice::class);

        $exchange->exchange($token);
    }

    /**
     * Define the test environment: in-memory sqlite + stub device model +
     * secret config.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('authentication.device.model', StubDevice::class);
        $config->set('authentication.device.table', 'stub_devices');
    }

    /**
     * Build a `RefreshTokenExchange` wired to the test collaborators.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function makeExchange(): RefreshTokenExchange
    {
        $app = $this->app;

        assert($app !== null);

        return new RefreshTokenExchange(
            $this->tokens,
            $app->make(ConnectionResolverInterface::class),
            $this->events,
            $this->resolver,
            self::GUARD_NAME,
        );
    }

    /**
     * Encode a refresh-token-style JWT with `iat`, `exp`, and `typ = refresh`
     * claims.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encodeRefreshToken(array $claims): string
    {
        $now = $this->now->getTimestamp();

        return JWT::encode(array_merge($claims, [
            'iat' => $now,
            'exp' => $now + (self::REFRESH_TTL * 60),
            'typ' => TokenType::REFRESH->value,
        ]), self::SECRET, self::ALGORITHM);
    }

    /**
     * Swap the configured device model so the exchange resolves the supplied
     * in-memory device through `find()` instead of issuing a real polymorphic
     * query.
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @return void
     */
    private function swapDeviceModelToInMemoryInstance(StubDevice $device): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->with($device->id)
            ->andReturn($device);
        $builder->shouldReceive('find')
            ->andReturn(null);

        StubInjectableDevice::$injectedBuilder = $builder;

        config()->set('authentication.device.model', StubInjectableDevice::class);
    }
}
