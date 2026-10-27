<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Random\RandomException;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;
use Tests\Unit\Stubs\StubBareDevice;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubInjectableDevice;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for the `RefreshTokenExchange` service that fill in the few
 * branches not covered by the JwtGuardRefreshTest's end-to-end coverage:
 *
 * - invalid `device.model` config -> refresh fails fast with an explicit
 *   configuration exception rather than falling through to `device_unknown`.
 * - resolver throws `UnresolvableIdentityException` -> the misconfiguration
 *   propagates out of the exchange instead of becoming a refresh failure.
 * - device model outside the explicit `EloquentDevice` boundary is rejected.
 * - a `did` that cannot be a key of the device model is `device_unknown`
 *   without a query, and a database error on a well-formed `did` propagates.
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

    /** @var string Kid the test secret is registered under. */
    private const string KID = 'test-kid';

    /** @var string HMAC algorithm shared with the test fixtures. */
    private const string ALGORITHM = 'HS256';

    /** @var int Access-token TTL minutes. */
    private const int ACCESS_TTL = 15;

    /** @var int Refresh-token TTL minutes. */
    private const int REFRESH_TTL = 60 * 24 * 30;

    /** @var string Guard name forwarded to the exchange constructor. */
    private const string GUARD_NAME = 'jwt-test';

    /** @var string Well-formed device id for lookups that reach the builder. */
    private const string DEVICE_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /** @var \Mockery\MockInterface Identity provider mock that reloads the device owner. */
    private MockInterface $provider;

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

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->events   = \Mockery::mock(Dispatcher::class);
        $this->tokens   = new JwtTokenService(
            JwtKeyring::fromKeyMap([self::KID => self::SECRET], self::KID, self::ALGORITHM),
            self::GUARD_NAME,
            self::ACCESS_TTL,
            self::REFRESH_TTL,
        );

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
     * After `setDispatcher()`, failures go to the new dispatcher and no longer
     * reach the one the exchange was built with.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testSetDispatcherRoutesLaterFailuresToTheNewDispatcher(): void
    {
        $exchange = $this->makeExchange();

        $replacement = \Mockery::mock(Dispatcher::class);
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->guard  === self::GUARD_NAME
                    && $event->reason === RefreshFailureReason::TOKEN_INVALID),
            );

        $this->events->shouldNotReceive('dispatch');

        self::assertSame($exchange, $exchange->setDispatcher($replacement));
        self::assertNull($exchange->exchange('not-a-jwt'));
    }

    /**
     * An empty `authentication.device.model` config is now an explicit
     * configuration error rather than a silent `device_unknown` refresh
     * failure.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeThrowsWhenConfiguredDeviceModelClassIsEmpty(): void
    {
        config()->set('authentication.device.model', '');

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => '01HZZZZZZZZZZZZZZZZZZZZZZZ',
            'jti' => 'rotation-id',
        ]);

        $this->expectException(InvalidDeviceModelConfigurationException::class);

        $exchange->exchange($token);
    }

    /**
     * An `UnresolvableIdentityException` thrown by the resolver is a
     * misconfiguration: it propagates out of the exchange as a server error
     * instead of being reported as a refresh failure, and the stored rotation
     * is left untouched.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangePropagatesUnresolvableIdentityException(): void
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
        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange  = $this->makeExchange();
        $exception = new UnresolvableIdentityException('cannot resolve');

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andThrow($exception);

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldNotReceive('dispatch');

        try {
            $exchange->exchange($token);
            self::fail('Expected the UnresolvableIdentityException to propagate.');
        } catch (UnresolvableIdentityException $caught) {
            self::assertSame($exception, $caught);
        }

        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $device->fresh()?->getRefreshKey());
    }

    /**
     * A principal acting within a `CanBeActive` tenant that reports inactive is
     * rejected with `tenant_inactive`, attributed to the device, and no
     * rotation happens.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeDispatchesTenantInactiveWhenPrincipalTenantIsInactive(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 10]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '10',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->once()->andReturnFalse();

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->once()->andReturn($tenant);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::TENANT_INACTIVE
                    && $event->deviceId === $device->id),
            );

        self::assertNull($exchange->exchange($token));
        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $device->fresh()?->getRefreshKey());
    }

    /**
     * Provider answers for owner key `9` of a `StubIdentity` device that are
     * not that owner.
     *
     * @return iterable<string, array{0: \Closure(): mixed}>
     */
    public static function provideAnswersThatAreNotTheDeviceOwner(): iterable
    {
        yield from [
            'no identity through the provider'          => [static fn (): null => null],
            'another identity model with the owner key' => [static fn (): StubPrincipal => (new StubPrincipal)->forceFill(['id' => 9])],
        ];
    }

    /**
     * The device owner is reloaded through the provider and must be that exact
     * owner: no identity, or an identity of another model that shares the owner
     * key, fails as `authenticatable_missing` before any principal is resolved.
     *
     * @param  \Closure(): mixed  $answer
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideAnswersThatAreNotTheDeviceOwner')]
    public function testExchangeRejectsAProviderAnswerThatIsNotTheDeviceOwner(\Closure $answer): void
    {
        $plainRotationId = 'stored-rotation-id';

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $answer());

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::AUTHENTICATABLE_MISSING
                    && $event->deviceId === $device->id),
            );

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        self::assertNull($exchange->exchange($token));
    }

    /**
     * Rows of `[failingRead]`: which read of the principal identifier fails,
     * the one the access token embeds or, after the access token is issued, the
     * one the refresh token embeds.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideIssuingFailures(): iterable
    {
        yield from [
            'issuing the access token'  => [1],
            'issuing the refresh token' => [2],
        ];
    }

    /**
     * Both tokens are issued before the rotation commits, so a failure while
     * issuing either of them leaves the stored digest untouched and the
     * presented refresh token still rotates on the next attempt. The failure is
     * injected through the principal identifier each token embeds.
     *
     * @param  int  $failingRead
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideIssuingFailures')]
    public function testExchangeLeavesTheRefreshTokenValidWhenIssuingFails(int $failingRead): void
    {
        $plainRotationId = 'stored-rotation-id';
        $storedDigest    = RefreshTokenHasher::hash($plainRotationId);

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 31]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '31',
            'refresh_key'          => $storedDigest,
        ])->save();

        $this->provider->shouldReceive('retrieveById')
            ->twice()
            ->with('31')
            ->andReturn($identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $reads = 0;

        $failing = \Mockery::mock(Principal::class);
        $failing->shouldReceive('getTenant')->andReturnNull();
        $failing->shouldReceive('getPrincipalIdentifier')
            ->times($failingRead)
            ->andReturnUsing(static function () use (&$reads, $failingRead): string {
                if (++$reads === $failingRead) {
                    throw new RandomException('random source unavailable');
                }

                return 'p-31';
            });

        $working = \Mockery::mock(Principal::class);
        $working->shouldReceive('getTenant')->andReturnNull();
        $working->shouldReceive('getPrincipalIdentifier')->andReturn('p-31');

        $this->resolver->shouldReceive('resolve')
            ->twice()
            ->with($identity)
            ->andReturn($failing, $working);

        $this->events->shouldNotReceive('dispatch');

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        try {
            $exchange->exchange($token);

            self::fail('The issuing failure should have propagated.');
        } catch (RandomException $exception) {
            self::assertSame('random source unavailable', $exception->getMessage());
        }

        self::assertSame($storedDigest, $this->storedDigest($device->id));

        self::assertNotNull($exchange->exchange($token));
        self::assertNotSame($storedDigest, $this->storedDigest($device->id));
    }

    /**
     * A refresh payload whose `jti` is not a string is rejected as
     * `token_invalid` and preserves the parseable device id on the emitted
     * failure event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeIncludesDeviceIdWhenRotationIdShapeIsInvalid(): void
    {
        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => 'device-non-string-jti',
            'jti' => 12345,
        ]);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::TOKEN_INVALID
                    && $event->deviceId === 'device-non-string-jti'),
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
     * @throws \Random\RandomException
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
        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
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
     * Fail-closed: a hinted principal whose identifier stringifies to `null` is
     * treated as unresolved and attributed to the device id carried by the
     * refresh token.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
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
        $this->expectOwnerReload($device, $identity);

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
     * Fail-closed: when the resolver resolves nothing for a hinted `pid`, the
     * exchange reports `principal_mismatch` rather than falling through to the
     * unresolved-principal branch, and no rotation happens.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeRejectsHintedPrincipalTheResolverCannotResolve(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 15]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '15',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturnNull();

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
        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $device->fresh()?->getRefreshKey());
    }

    /**
     * A refresh token without a `pid` whose identity has no default principal
     * fails as `principal_unresolved`, attributed to the device, and no
     * rotation happens.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeDispatchesPrincipalUnresolvedWhenNoDefaultPrincipalResolves(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 16]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '16',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturnNull();

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
        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $device->fresh()?->getRefreshKey());
    }

    /**
     * A `did` that cannot be a key of the configured device model names no
     * device: the exchange reports `device_unknown` without querying.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeRejectsMalformedDeviceIdWithoutQuerying(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldNotReceive('find');

        StubInjectableDevice::$injectedBuilder = $builder;

        config()->set('authentication.device.model', StubInjectableDevice::class);

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => 'not-a-valid-uuid',
            'jti' => 'rotation-id',
        ]);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::DEVICE_UNKNOWN
                    && $event->deviceId === 'not-a-valid-uuid'),
            );

        self::assertNull($exchange->exchange($token));
    }

    /**
     * A database error on a well-formed `did` propagates to the caller as a
     * server error instead of being reported as an unknown device.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangePropagatesQueryExceptionDuringDeviceLookup(): void
    {
        $failure = new QueryException('testing', 'select', [], new \PDOException('server has gone away'));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('find')
            ->once()
            ->with(self::DEVICE_ID)
            ->andThrow($failure);

        StubInjectableDevice::$injectedBuilder = $builder;

        config()->set('authentication.device.model', StubInjectableDevice::class);

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => self::DEVICE_ID,
            'jti' => 'rotation-id',
        ]);

        $this->events->shouldNotReceive('dispatch');

        $this->expectExceptionObject($failure);

        $exchange->exchange($token);
    }

    /**
     * The exchange rejects configured device models that implement the generic
     * `Device` contract but do not satisfy the explicit `EloquentDevice`
     * persistence boundary.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeThrowsWhenConfiguredDeviceModelDoesNotImplementEloquentDevice(): void
    {
        config()->set('authentication.device.model', StubBareDevice::class);

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'did' => 'bare-device-1',
            'jti' => 'rotation-id',
        ]);

        $this->expectException(InvalidDeviceModelConfigurationException::class);
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
            $this->provider,
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
            'grd' => self::GUARD_NAME,
        ]), self::SECRET, self::ALGORITHM, self::KID);
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
        $builder->shouldReceive('useWritePdo')
            ->atLeast()->once()
            ->andReturnSelf();
        $builder->shouldReceive('find')
            ->with($device->id)
            ->andReturn($device);
        $builder->shouldReceive('find')
            ->andReturn(null);

        StubInjectableDevice::$injectedBuilder = $builder;

        config()->set('authentication.device.model', StubInjectableDevice::class);
    }

    /**
     * Expect the exchange's identity provider to reload the device's owner
     * once, by the owner key stored on the device row, and answer with the
     * supplied identity.
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @param  mixed  $identity
     * @return void
     */
    private function expectOwnerReload(StubDevice $device, mixed $identity): void
    {
        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with($device->getAttribute('authenticatable_id'))
            ->andReturn($identity);
    }

    /**
     * Read the refresh digest stored on the device row.
     *
     * @param  string  $deviceId
     * @return mixed
     */
    private function storedDigest(string $deviceId): mixed
    {
        return DB::table('stub_devices')->where('id', $deviceId)->value('refresh_key');
    }
}
