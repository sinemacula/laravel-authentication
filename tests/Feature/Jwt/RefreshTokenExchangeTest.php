<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Random\RandomException;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;
use SineMacula\Laravel\Authentication\Runtime\CredentialTimebox;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithDevices;
use Tests\Unit\Stubs\PlainPrincipalFixture;
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
    use InteractsWithDevices, MockeryPHPUnitIntegration;

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

    /** @var int Refresh grace window, in seconds. */
    private const int GRACE = 30;

    /** @var string Plaintext rotation id the protocol tests present. */
    private const string ROTATION_ID = 'presented-rotation-id';

    /** @var string Guard name forwarded to the exchange constructor. */
    private const string GUARD_NAME = 'jwt-test';

    /** @var string IP address every exchange comes from. */
    private const string CLIENT_IP = '198.51.100.7';

    /** @var string Well-formed device id for lookups that reach the builder. */
    private const string DEVICE_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /** @var \Mockery\MockInterface Identity provider mock that reloads the device owner. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface Resolver mock. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface Dispatcher mock. */
    private MockInterface $events;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\AudiencePolicy Audience policy the exchange resolves from the container. */
    private MockInterface $audience;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\AttemptLimiter Limiter the exchange resolves from the container. */
    private MockInterface $limiter;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private JwtTokenService $tokens;

    /** @var \SineMacula\Laravel\Authentication\Runtime\GuardContext The context of the guard every exchange is bound to. */
    private GuardContext $context;

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /** @var list<object> Events the exchange dispatched, when recorded. */
    private array $dispatched = [];

    /** @var list<\SineMacula\Laravel\Authentication\Events\AuthenticationFailed> Failures the exchanges returned. */
    private array $failures = [];

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
            new TokenLifetimes(self::ACCESS_TTL, self::REFRESH_TTL, 60 * 24 * 180, self::GRACE),
            30,
        );

        $this->context = new GuardContext(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, Request::create('/'), new CredentialTimebox(new Timebox));

        $this->audience = \Mockery::mock(AudiencePolicy::class);
        $this->audience->shouldReceive('allowsMethod')->andReturn(true)->byDefault();
        $this->audience->shouldReceive('admit')->andReturn(null)->byDefault();
        $this->audience->shouldReceive('lifetimes')->andReturn($this->tokens->lifetimes())->byDefault();

        $this->limiter = \Mockery::mock(AttemptLimiter::class);
        $this->limiter->shouldReceive('blocked')->andReturn(null)->byDefault();
        $this->limiter->shouldReceive('recordFailure')->byDefault();

        $this->app?->instance(AudiencePolicy::class, $this->audience);
        $this->app?->instance(AttemptLimiter::class, $this->limiter);

        self::createDeviceTable('stub_devices');
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
     * After the guard's context is rebound to another dispatcher, the
     * revocation of a replayed device goes to the new dispatcher and no longer
     * reaches the one the exchange was built with.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARebindOfTheContextsDispatcherRoutesLaterRevocationsToIt(): void
    {
        $device   = $this->seedRotatedDevice(42, rotatedSecondsAgo: 5);
        $exchange = $this->makeExchange();

        $replacement = \Mockery::mock(Dispatcher::class);
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof DeviceRevoked
                && $event->context->guard === self::GUARD_NAME
                && $event->reason         === RevocationReason::ROTATION_REUSE));

        $this->events->shouldNotReceive('dispatch');

        $this->context->rebindEvents($replacement);

        $failure = $this->refused($exchange->exchange($this->tokenFor($device, 'a-replayed-rotation-id'), self::client()));

        self::assertSame(FailureReason::ROTATION_REUSE, $failure->reason);
    }

    /**
     * A failure is returned for the caller to report, never dispatched by the
     * exchange itself, and carries the guard and the client.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testAFailureIsReturnedNotDispatched(): void
    {
        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($this->makeExchange()->exchange('not-a-jwt', self::client()));

        self::assertSame(AuthenticationFlow::REFRESH, $failure->flow);
        self::assertSame(FailureReason::TOKEN_INVALID, $failure->reason);
        self::assertSame(self::GUARD_NAME, $failure->context->guard);
        self::assertSame(self::CLIENT_IP, $failure->context->client->ip);
        self::assertNull($failure->context->identity);
        self::assertNull($failure->context->deviceId);
        self::assertNull($failure->identifier);
        self::assertNull($failure->retryAfter);
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

        $exchange->exchange($token, self::client());
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
            ...self::liveSession(self::GUARD_NAME),
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
            $exchange->exchange($token, self::client());
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
            ...self::liveSession(self::GUARD_NAME),
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
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn(77);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::TENANT_INACTIVE, $failure->reason);
        self::assertSame($device->id, $failure->context->deviceId);
        self::assertSame($identity, $failure->context->identity);
        self::assertSame($principal, $failure->context->principal);
        self::assertNull($failure->context->tenant);
        self::assertSame('password', $failure->context->method);
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
     * key, fails as `identity_unknown` before any principal is resolved. The
     * failure is about the device row, so it names the owner and the principal
     * the row records.
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
            ...self::liveSession(self::GUARD_NAME, new PlainPrincipalFixture('p-9')),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $answer());

        $this->swapDeviceModelToInMemoryInstance($device);

        $exchange = $this->makeExchange();

        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldNotReceive('dispatch');

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $failure->reason);
        self::assertSame($device->id, $failure->context->deviceId);
        self::assertNull($failure->context->identity);
        self::assertSame('9', $failure->context->identityId);
        self::assertSame(PlainPrincipalFixture::class, $failure->context->principalMorphClass);
        self::assertSame('p-9', $failure->context->principalId);
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
            'issuing the access token'  => [2],
            'issuing the refresh token' => [3],
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
            ...self::liveSession(self::GUARD_NAME),
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

        $device->forceFill(['principal_type' => $failing::class, 'principal_id' => 'p-31'])->save();

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
            $exchange->exchange($token, self::client());

            self::fail('The issuing failure should have propagated.');
        } catch (RandomException $exception) {
            self::assertSame('random source unavailable', $exception->getMessage());
        }

        self::assertSame($storedDigest, $this->storedDigest($device->id));

        self::assertInstanceOf(ExchangedRefresh::class, $exchange->exchange($token, self::client()));
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

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::TOKEN_INVALID, $failure->reason);
        self::assertSame('device-non-string-jti', $failure->context->deviceId);
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
            ...self::liveSession(self::GUARD_NAME),
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
            ->times(4)
            ->andReturn('p-12');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $device->forceFill(['principal_type' => $principal::class, 'principal_id' => 'p-12'])->save();

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

        $result = $exchange->exchange($token, self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
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
            ...self::liveSession(self::GUARD_NAME),
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

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $failure->reason);
        self::assertSame($device->id, $failure->context->deviceId);
    }

    /**
     * Fail-closed: when the resolver resolves nothing for a hinted `pid`, the
     * exchange reports `principal_mismatch` rather than falling through to the
     * unresolved-principal branch, and no rotation happens. Once the owner is
     * read the failure names it, and no principal: the one the device records
     * does not stand in for the one that did not resolve.
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
            ...self::liveSession(self::GUARD_NAME, new PlainPrincipalFixture('p-recorded')),
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

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $failure->reason);
        self::assertSame($device->id, $failure->context->deviceId);
        self::assertSame('15', $failure->context->identityId);
        self::assertNull($failure->context->principalMorphClass);
        self::assertNull($failure->context->principalId);
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
            ...self::liveSession(self::GUARD_NAME),
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

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $failure->reason);
        self::assertSame($device->id, $failure->context->deviceId);
        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $device->fresh()?->getRefreshKey());
    }

    /**
     * Rows of `[idle deadline, absolute deadline]` for sessions that have ended
     * or never had deadlines, relative to the frozen clock in seconds.
     *
     * @return iterable<string, array{0: ?int, 1: ?int}>
     */
    public static function provideEndedSessions(): iterable
    {
        yield from [
            'idle reached'         => [0, 3600],
            'absolute reached'     => [3600, 0],
            'no idle deadline'     => [null, 3600],
            'no absolute deadline' => [3600, null],
        ];
    }

    /**
     * A device whose session has ended, or that has no deadlines, fails as
     * `session_expired` before its owner is loaded or its digest compared, and
     * nothing is written: the device is not revoked.
     *
     * @param  ?int  $idleIn
     * @param  ?int  $absoluteIn
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideEndedSessions')]
    public function testExchangeRejectsAnEndedSessionWithoutWriting(?int $idleIn, ?int $absoluteIn): void
    {
        $plainRotationId = 'stored-rotation-id';

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'guard'                => self::GUARD_NAME,
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
            'idle_expires_at'      => $idleIn     === null ? null : $this->now->copy()->addSeconds($idleIn),
            'absolute_expires_at'  => $absoluteIn === null ? null : $this->now->copy()->addSeconds($absoluteIn),
        ])->save();

        $this->swapDeviceModelToInMemoryInstance($device);

        $before = (array) DB::table('stub_devices')->where('id', $device->id)->first();

        $this->provider->shouldNotReceive('retrieveById');
        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldNotReceive('dispatch');

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $failure = $this->refused($this->makeExchange()->exchange($token, self::client()));

        self::assertSame(FailureReason::SESSION_EXPIRED, $failure->reason);
        self::assertSame($device->id, $failure->context->deviceId);
        self::assertSame($before, (array) DB::table('stub_devices')->where('id', $device->id)->first());
    }

    /**
     * A current rotation id is rotated to its successor: the row records the
     * presented id as the previous one and the exchange's time as the rotation
     * time, moves the idle deadline to the idle lifetime from that time, and
     * leaves the absolute deadline alone. The new refresh token carries the
     * successor, and the returned device mirrors the row with nothing left to
     * save.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeRotatesTheCurrentRotationIdToItsSuccessor(): void
    {
        $absolute = $this->now->copy()->addDays(100);
        $device   = $this->seedDevice(32, [
            'refresh_key'         => RefreshTokenHasher::hash(self::ROTATION_ID),
            'idle_expires_at'     => $this->now->copy()->addMinute(),
            'absolute_expires_at' => $absolute,
        ]);

        $this->expectRefreshContext(32);
        $this->recordEvents();

        $result = $this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);

        $successor    = RefreshTokenHasher::successor(self::ROTATION_ID);
        $expectedIdle = $this->now->getTimestamp() + (self::REFRESH_TTL * 60);
        $stored       = StubDevice::query()->findOrFail($device->id);

        self::assertSame(RefreshTokenHasher::hash($successor), $stored->refresh_key);
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $stored->previous_refresh_key);
        self::assertSame($this->now->getTimestamp(), $stored->refresh_rotated_at?->getTimestamp());
        self::assertSame($expectedIdle, $stored->idle_expires_at?->getTimestamp());
        self::assertSame($absolute->getTimestamp(), $stored->absolute_expires_at?->getTimestamp());
        self::assertSame($successor, $this->refreshClaims($result->tokens->refreshToken)[Claims::JWT_ID->value]);
        self::assertSame($expectedIdle, $this->refreshClaims($result->tokens->refreshToken)[Claims::EXPIRES_AT->value]);
        self::assertSame($stored->refresh_key, $result->device->getRefreshKey());
        self::assertSame($stored->previous_refresh_key, $result->device->getPreviousRefreshKey());
        self::assertSame($expectedIdle, $result->device->getIdleExpiresAt()?->getTimestamp());
        self::assertFalse($result->device->isDirty());
        self::assertSame([], $this->dispatched);
    }

    /**
     * The rotation id the current one replaced, presented inside the grace
     * window, gets the session's current credential: a pair whose refresh token
     * carries the current rotation id and expires at the stored idle deadline.
     * No rotation state is written, so the window stays anchored at the
     * rotation that opened it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testGraceRetryGetsTheCurrentCredentialWithoutWriting(): void
    {
        $current = RefreshTokenHasher::successor(self::ROTATION_ID);
        $idle    = $this->now->copy()->addDays(20);
        $device  = $this->seedRotatedDevice(33, rotatedSecondsAgo: 29, idle: $idle);
        $before  = $this->row($device);

        $this->expectRefreshContext(33);
        $this->recordEvents();

        $result = $this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
        self::assertSame($current, $this->refreshClaims($result->tokens->refreshToken)[Claims::JWT_ID->value]);
        self::assertSame($idle->getTimestamp(), $this->refreshClaims($result->tokens->refreshToken)[Claims::EXPIRES_AT->value]);
        self::assertSame($before, $this->row($device));
        self::assertSame([], $this->dispatched);
    }

    /**
     * Rows of `[how the presented rotation id relates to the device, seconds
     * since the rotation, grace window in seconds]` for tokens that prove a
     * replay.
     *
     * @return iterable<string, array{0: string, 1: int, 2: int}>
     */
    public static function provideReplays(): iterable
    {
        yield from [
            'previous id when the window ends'        => ['previous', 30, 30],
            'previous id after the window'            => ['previous', 3600, 30],
            'previous id with grace disabled'         => ['previous', 0, 0],
            'an older id inside the window'           => ['older', 5, 30],
            'previous id the row did not rotate from' => ['unrelated', 5, 30],
            'an id the device never issued'           => ['foreign', 5, 30],
            'previous digest without a rotation time' => ['no rotation time', 5, 30],
            'rotation time without a previous digest' => ['no previous digest', 5, 30],
        ];
    }

    /**
     * A validly signed token for a live device whose rotation id is neither the
     * current one nor the previous one inside the grace window proves the token
     * was replayed: the device is revoked with reason `rotation_reuse` (its
     * time and reason recorded, both digests cleared), `DeviceRevoked` and
     * `AuthenticationFailed` are dispatched, and nothing is issued.
     *
     * @param  string  $presented
     * @param  int  $rotatedSecondsAgo
     * @param  int  $grace
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideReplays')]
    public function testReplayRevokesTheDevice(string $presented, int $rotatedSecondsAgo, int $grace): void
    {
        $device = $this->seedRotatedDevice(34, rotatedSecondsAgo: $rotatedSecondsAgo);

        $changes = match ($presented) {
            'unrelated'          => ['refresh_key' => RefreshTokenHasher::hash('set-outside-a-rotation')],
            'no rotation time'   => ['refresh_rotated_at' => null],
            'no previous digest' => ['previous_refresh_key' => null],
            default              => [],
        };

        DB::table('stub_devices')->where('id', $device->id)->update([...$changes, 'updated_at' => $this->now]);

        $rotationId = match ($presented) {
            'older'   => 'the-id-before-the-previous-one',
            'foreign' => 'never-issued-rotation-id',
            default   => self::ROTATION_ID,
        };

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $this->refused($this->makeExchange($grace)->exchange($this->tokenFor($device, $rotationId), self::client()));

        $this->assertRevokedForReuse($device);
    }

    /**
     * The grace guarantee covers only the immediately previous rotation id:
     * after two quick rotations, a delayed retry of the first id is a replay
     * even though both rotations fall inside the window.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testOnlyTheImmediatelyPreviousRotationIdIsHonoured(): void
    {
        $first  = self::ROTATION_ID;
        $device = $this->seedDevice(35, ['refresh_key' => RefreshTokenHasher::hash($first)]);

        $this->expectRefreshContext(35, 2);
        $this->recordEvents();

        $second = $this->makeExchange()->exchange($this->tokenFor($device, $first), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $second);

        $third = $this->makeExchange()->exchange($second->tokens->refreshToken, self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $third);
        $this->refused($this->makeExchange()->exchange($this->tokenFor($device, $first), self::client()));

        $this->assertRevokedForReuse($device);
    }

    /**
     * A device that holds no refresh credential cannot tell a replay from
     * anything else, so its tokens are rejected as `refresh_key_missing`
     * without revoking it or writing anything.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testDeviceWithoutARefreshCredentialIsRejectedWithoutRevoking(): void
    {
        $device = $this->seedDevice(36, ['refresh_key' => null, 'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $before = $this->row($device);

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client()));
        self::assertSame($before, $this->row($device));
        self::assertSame([FailureReason::REFRESH_KEY_MISSING], $this->failureReasons());
    }

    /**
     * A refresh for a principal the device no longer records (the session was
     * switched to another one) fails as `device_principal_mismatch`, without
     * revoking the device or writing to it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARefreshAsAPrincipalTheDeviceNoLongerRecordsIsRefused(): void
    {
        $device = $this->seedDevice(44, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID), 'principal_id' => 'p-switched']);
        $before = $this->row($device);

        $this->expectRefreshContext(44);
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client()));
        self::assertSame([FailureReason::DEVICE_PRINCIPAL_MISMATCH], $this->failureReasons());
        self::assertSame($before, $this->row($device));
    }

    /**
     * A device that holds no refresh credential and whose session has ended
     * fails as `session_expired`, not `refresh_key_missing`: the session is
     * judged before the credential, and nothing is written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testEndedSessionIsReportedBeforeAMissingRefreshCredential(): void
    {
        $device = $this->seedDevice(36, ['refresh_key' => null, 'idle_expires_at' => $this->now]);
        $before = $this->row($device);

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client()));
        self::assertSame($before, $this->row($device));
        self::assertSame([FailureReason::SESSION_EXPIRED], $this->failureReasons());
    }

    /**
     * A device loaded without its previous digest cannot be judged for a token
     * that is not current: the missing column is reported instead of the token
     * being read as a replay that revokes the device.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testDeviceLoadedWithoutItsPreviousDigestIsReportedNotRevoked(): void
    {
        $device = $this->seedRotatedDevice(37, rotatedSecondsAgo: 5);

        $loaded = new StubDevice;
        $loaded->setRawAttributes(array_diff_key((array) DB::table('stub_devices')->where('id', $device->id)->first(), ['previous_refresh_key' => true]), true);
        $loaded->exists = true;

        $this->swapDeviceModelToInMemoryInstance($loaded, false);

        $this->events->shouldNotReceive('dispatch');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `previous_refresh_key` attribute is not loaded');

        $this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client());
    }

    /**
     * Revoking a device records the time and reason, clears both digests,
     * mirrors the revocation on the in-memory device, and dispatches
     * `DeviceRevoked` once. Revoking it again changes nothing: the first
     * revocation's time and reason are kept and no event is dispatched.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRevokingADeviceIsIdempotent(): void
    {
        $device = $this->seedRotatedDevice(38, rotatedSecondsAgo: 5);

        $this->recordEvents();

        self::assertTrue($this->makeExchange()->revokeDevice($device, RevocationReason::ROTATION_REUSE, self::client()));
        self::assertSame($this->now->getTimestamp(), $device->revoked_at?->getTimestamp());
        self::assertSame('rotation_reuse', $device->getRevokedReason());
        self::assertNull($device->getRefreshKey());
        self::assertFalse($device->isDirty());

        $first = $this->row($device);

        Carbon::setTestNow($this->now->copy()->addMinute());

        self::assertFalse($this->makeExchange()->revokeDevice(StubDevice::query()->findOrFail($device->id), RevocationReason::ROTATION_REUSE, self::client()));
        self::assertSame($first, $this->row($device));
        self::assertCount(1, $this->dispatched);
        self::assertInstanceOf(DeviceRevoked::class, $this->dispatched[0]);
        self::assertSame($device, $this->dispatched[0]->context->device);
        self::assertSame(self::GUARD_NAME, $this->dispatched[0]->context->guard);
        self::assertSame(self::CLIENT_IP, $this->dispatched[0]->context->client->ip);
        self::assertSame('password', $this->dispatched[0]->context->method);
    }

    /**
     * A parallel refresh with the same token that rotates first, between this
     * exchange's read and its swap, makes this exchange a grace retry: the swap
     * misses, the row is judged again, and this exchange gets the same current
     * credential the winner got, without writing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testLostRotationToAParallelRefreshIsAGraceRetry(): void
    {
        $device = $this->seedDevice(39, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(39);
        $this->recordEvents();
        $this->beforeTheSwap(fn () => $this->rotateOnTheRow($device, self::ROTATION_ID));

        $result = $this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
        self::assertSame(RefreshTokenHasher::successor(self::ROTATION_ID), $this->refreshClaims($result->tokens->refreshToken)[Claims::JWT_ID->value]);
        self::assertSame(RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)), $this->storedDigest($device->id));
        self::assertSame($result->device->getRefreshKey(), $this->storedDigest($device->id));
        self::assertSame([], $this->dispatched);
    }

    /**
     * The row is judged again at the exchange's own time, not the clock's: a
     * competing rotation that leaves the window open at the exchange's time is
     * a grace retry, even when the clock has moved past the window by the time
     * the row is read again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testLostRotationIsJudgedAtTheExchangesOwnTime(): void
    {
        $device = $this->seedDevice(40, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(40);
        $this->recordEvents();
        $this->beforeTheSwap(function () use ($device): void {
            $this->rotateOnTheRow($device, self::ROTATION_ID);

            Carbon::setTestNow($this->now->copy()->addMinutes(5));
        });

        self::assertInstanceOf(ExchangedRefresh::class, $this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client()));
        self::assertSame([], $this->dispatched);
    }

    /**
     * With grace disabled, a parallel refresh that rotates first leaves the
     * loser holding a replaced token: the row judged again proves a replay, and
     * the device is revoked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testLostRotationWithGraceDisabledRevokesTheDevice(): void
    {
        $device = $this->seedDevice(41, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(41);
        $this->recordEvents();
        $this->beforeTheSwap(fn () => $this->rotateOnTheRow($device, self::ROTATION_ID));

        $this->refused($this->makeExchange(0)->exchange($this->tokenFor($device, self::ROTATION_ID), self::client()));

        $this->assertRevokedForReuse($device);
    }

    /**
     * Rows of `[competing change committed between the read and the swap,
     * failure the row judged again gives]`.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideCompetingChanges(): iterable
    {
        yield from [
            'revoked'                  => ['revoked', FailureReason::DEVICE_REVOKED],
            'deleted'                  => ['deleted', FailureReason::DEVICE_UNKNOWN],
            'ended'                    => ['ended', FailureReason::SESSION_EXPIRED],
            'credential cleared'       => ['cleared', FailureReason::REFRESH_KEY_MISSING],
            'absolute deadline moved'  => ['shortened', FailureReason::ROTATION_CONFLICT],
            'idle deadline moved'      => ['extended', FailureReason::ROTATION_CONFLICT],
            'rotated to another owner' => ['reowned', FailureReason::IDENTITY_UNKNOWN],
            'switched to another one'  => ['switched', FailureReason::DEVICE_PRINCIPAL_MISMATCH],
        ];
    }

    /**
     * When the swap misses for any other reason, the row judged again decides
     * the failure: a device revoked, deleted, ended, or stripped of its
     * credential in between fails for that reason; a token that is still
     * current, because only a deadline moved, fails as `rotation_conflict`; and
     * a grace retry whose row now has another owner fails as
     * `identity_unknown`, or, when the row now records another principal,
     * `device_principal_mismatch`. None of them revokes the device, and the
     * swap is never tried twice.
     *
     * @param  string  $change
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideCompetingChanges')]
    public function testLostRotationFailsWithWhatTheRowNowSays(string $change, FailureReason $reason): void
    {
        $device = $this->seedDevice(42, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(42);
        $this->recordEvents();

        $swaps = 0;

        DB::connection()->listen(static function (QueryExecuted $query) use (&$swaps): void {
            $swaps += str_contains($query->sql, 'refresh_rotated_at') && str_contains($query->sql, 'is null') ? 1 : 0;
        });

        $this->beforeTheSwap(fn () => $this->compete($change, $device));

        $this->refused($this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client()));
        self::assertSame([$reason], $this->failureReasons());
        self::assertSame(1, $swaps);
        self::assertNotContains(DeviceRevoked::class, array_map(static fn (object $event): string => $event::class, $this->dispatched));
        self::assertNotSame('rotation_reuse', $this->row($device)['revoked_reason'] ?? null);
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

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::DEVICE_UNKNOWN, $failure->reason);
        self::assertSame('not-a-valid-uuid', $failure->context->deviceId);
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

        $exchange->exchange($token, self::client());
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

        $exchange->exchange($token, self::client());
    }

    /**
     * Once failed refreshes fill a limit, the exchange stops before looking the
     * device up: it reports and returns `rate_limited` with the wait, and
     * counts nothing more. The limits are asked about the token's device and
     * the client's IP address.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testABlockedExchangeIsRefusedBeforeTheLookup(): void
    {
        $this->limiter->shouldReceive('blocked')
            ->once()
            ->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->guard === self::GUARD_NAME
                && $subject->flow                                                            === AttemptFlow::REFRESH
                && $subject->identifier                                                      === self::DEVICE_ID
                && $subject->identifierType                                                  === null
                && $subject->ip                                                              === self::CLIENT_IP))
            ->andReturn(42);
        $this->limiter->shouldNotReceive('recordFailure');
        $this->provider->shouldNotReceive('retrieveById');

        $this->recordEvents();

        DB::connection()->enableQueryLog();

        $failure = $this->makeExchange()->exchange($this->encodeRefreshToken(['did' => self::DEVICE_ID, 'jti' => self::ROTATION_ID]), self::client());

        self::assertSame([], DB::connection()->getQueryLog());
        self::assertSame([], $this->dispatched);
        self::assertInstanceOf(AuthenticationFailed::class, $failure);
        self::assertSame(self::GUARD_NAME, $failure->context->guard);
        self::assertSame(FailureReason::RATE_LIMITED, $failure->reason);
        self::assertSame(self::DEVICE_ID, $failure->context->deviceId);
        self::assertSame(42, $failure->retryAfter);
    }

    /**
     * Every failure is counted against the token's device and the client's IP
     * address before it is reported; a token that does not parse names no
     * device, so it counts against the IP address only.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testEveryFailureIsCountedAgainstTheDeviceAndTheIpAddress(): void
    {
        $counted = [];

        $this->limiter->shouldReceive('recordFailure')
            ->twice()
            ->andReturnUsing(function (AttemptSubject $subject) use (&$counted): void {
                self::assertSame([], $this->dispatched);
                self::assertSame(AttemptFlow::REFRESH, $subject->flow);
                self::assertSame(self::CLIENT_IP, $subject->ip);

                $counted[] = $subject->identifier;
            });

        $this->recordEvents();

        $unknown = $this->encodeRefreshToken(['did' => self::DEVICE_ID, 'jti' => self::ROTATION_ID]);

        $this->refused($this->makeExchange()->exchange($unknown, self::client()));

        $this->failures = [];

        $this->refused($this->makeExchange()->exchange('not-a-jwt', self::client()));
        self::assertSame([self::DEVICE_ID, null], $counted);
        self::assertSame([FailureReason::TOKEN_INVALID], $this->failureReasons());
    }

    /**
     * A successful exchange is not counted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testASuccessfulExchangeIsNotCounted(): void
    {
        $device = $this->seedDevice(41, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(41);
        $this->limiter->shouldNotReceive('recordFailure');

        self::assertInstanceOf(ExchangedRefresh::class, $this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client()));
    }

    /**
     * Rows of `[guard]` a device may record other than the exchanging guard.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideOtherGuards(): iterable
    {
        yield from [
            'another guard' => ['admin'],
            'no guard'      => [null],
        ];
    }

    /**
     * A device of another guard, or of none, fails as `device_guard_mismatch`
     * before its rotation id is judged, so even a replayed token of it revokes
     * nothing, and its owner is never loaded.
     *
     * @param  ?string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideOtherGuards')]
    public function testADeviceOfAnotherGuardIsRefusedWithoutRevokingIt(?string $guard): void
    {
        $device = $this->seedDevice(42, ['guard' => $guard, 'refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $before = $this->row($device);

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $failure = $this->refused($this->makeExchange()->exchange($this->tokenFor($device, 'a-replayed-rotation-id'), self::client()));

        self::assertSame([FailureReason::DEVICE_GUARD_MISMATCH], $this->failureReasons());
        self::assertSame([], $this->dispatched);
        self::assertSame(self::GUARD_NAME, $failure->context->guard);
        self::assertSame($device->id, $failure->context->device?->getDeviceIdentifier());
        self::assertSame($device->id, $failure->context->deviceId);
        self::assertSame($before, $this->row($device));
    }

    /**
     * The method that started the session must still be one the guard lets
     * start its sessions; a device that records no method fails closed without
     * asking. Neither writes anything.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testTheMethodThatStartedTheSessionMustStillBeAllowed(): void
    {
        $removed  = $this->seedDevice(43, ['sign_in_method' => 'sso', 'refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $unstated = $this->seedDevice(43, ['sign_in_method' => null, 'refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $before   = [$this->row($removed), $this->row($unstated)];

        $this->audience->shouldReceive('allowsMethod')->once()->with(self::GUARD_NAME, 'sso')->andReturn(false);
        $this->audience->shouldNotReceive('admit');
        $this->expectRefreshContext(43, 2);
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($removed, self::ROTATION_ID), self::client()));
        $this->refused($this->makeExchange()->exchange($this->tokenFor($unstated, self::ROTATION_ID), self::client()));
        self::assertSame([FailureReason::METHOD_NOT_ALLOWED, FailureReason::METHOD_NOT_ALLOWED], $this->failureReasons());
        self::assertSame($before, [$this->row($removed), $this->row($unstated)]);
    }

    /**
     * The guard's audience policy must still admit the owner as the principal,
     * asked without an identifier type; when it does not, the exchange fails as
     * `principal_ineligible` without writing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testThePolicyMustStillAdmitTheOwnerAsThePrincipal(): void
    {
        $device   = $this->seedDevice(44, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $before   = $this->row($device);
        $identity = $this->expectRefreshContext(44);

        $this->audience->shouldReceive('allowsMethod')->once()->with(self::GUARD_NAME, 'password')->andReturn(true);
        $this->audience->shouldReceive('admit')
            ->once()
            ->with(self::GUARD_NAME, $identity, \Mockery::type(Principal::class), null)
            ->andReturn(FailureReason::IDENTIFIER_UNVERIFIED);
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client()));
        self::assertSame([FailureReason::PRINCIPAL_INELIGIBLE], $this->failureReasons());
        self::assertSame($before, $this->row($device));
    }

    /**
     * A rotation moves the idle deadline by the idle lifetime the policy gives
     * the principal, not the guard's own.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARotationMovesTheIdleDeadlineByThePrincipalsLifetimes(): void
    {
        $device = $this->seedDevice(45, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(45);
        $this->audience->shouldReceive('lifetimes')
            ->once()
            ->with(self::GUARD_NAME, \Mockery::type(Principal::class))
            ->andReturn(new TokenLifetimes(self::ACCESS_TTL, 45, 60 * 24 * 180, self::GRACE));

        $result = $this->makeExchange()->exchange($this->tokenFor($device, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
        self::assertSame($this->now->getTimestamp() + (45 * 60), StubDevice::query()->findOrFail($device->id)->idle_expires_at?->getTimestamp());
        self::assertSame($this->now->getTimestamp() + (45 * 60), $this->refreshClaims($result->tokens->refreshToken)[Claims::EXPIRES_AT->value]);
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
     * Build a `RefreshTokenExchange` wired to the test collaborators, with the
     * given refresh grace window.
     *
     * @param  int  $grace
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function makeExchange(int $grace = self::GRACE): RefreshTokenExchange
    {
        $app = $this->app;

        assert($app !== null);

        $tokens = $grace === self::GRACE
            ? $this->tokens
            : new JwtTokenService(
                JwtKeyring::fromKeyMap([self::KID => self::SECRET], self::KID, self::ALGORITHM),
                self::GUARD_NAME,
                new TokenLifetimes(self::ACCESS_TTL, self::REFRESH_TTL, 60 * 24 * 180, $grace),
                30,
            );

        return new RefreshTokenExchange(
            $tokens,
            $this->context,
            $app->make(ConnectionResolverInterface::class),
            static fn (): mixed => $app->make('db.transactions'),
        );
    }

    /**
     * The client every exchange in these tests comes from.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext(self::CLIENT_IP, 'Exchange/1.0');
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
     * query. The device is reloaded first, unless told otherwise, so it carries
     * every column, as the exchange's own lookup would.
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @param  bool  $reload
     * @return void
     */
    private function swapDeviceModelToInMemoryInstance(StubDevice $device, bool $reload = true): void
    {
        if ($reload) {
            $device->refresh();
        }

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

    /**
     * Persist a live device owned by the `StubIdentity` with the given key,
     * with any further state.
     *
     * @param  int  $ownerId
     * @param  array<string, mixed>  $state
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function seedDevice(int $ownerId, array $state): StubDevice
    {
        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME, new PlainPrincipalFixture("p-{$ownerId}")),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => (string) $ownerId,
            ...$state,
        ])->save();

        return StubDevice::query()->findOrFail($device->id);
    }

    /**
     * Persist a live device that was rotated from `ROTATION_ID` to its
     * successor the given number of seconds ago.
     *
     * @param  int  $ownerId
     * @param  int  $rotatedSecondsAgo
     * @param  ?\Carbon\Carbon  $idle
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function seedRotatedDevice(int $ownerId, int $rotatedSecondsAgo, ?Carbon $idle = null): StubDevice
    {
        return $this->seedDevice($ownerId, [
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)),
            'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID),
            'refresh_rotated_at'   => $this->now->copy()->subSeconds($rotatedSecondsAgo),
            'idle_expires_at'      => $idle ?? $this->now->copy()->addDays(30),
        ]);
    }

    /**
     * Rotate the device's row from the given rotation id to its successor, as a
     * refresh that won a race would, optionally moving it to another owner, or
     * to another principal as a switch that won would.
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @param  string  $rotationId
     * @param  ?string  $ownerId
     * @param  ?string  $principalId
     * @return void
     */
    private function rotateOnTheRow(StubDevice $device, string $rotationId, ?string $ownerId = null, ?string $principalId = null): void
    {
        DB::table('stub_devices')->where('id', $device->id)->update([
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor($rotationId)),
            'previous_refresh_key' => RefreshTokenHasher::hash($rotationId),
            'refresh_rotated_at'   => $this->now,
            'authenticatable_id'   => $ownerId     ?? $device->getAttribute('authenticatable_id'),
            'principal_id'         => $principalId ?? $device->getAttribute('principal_id'),
        ]);
    }

    /**
     * Commit the named competing change to the device's row.
     *
     * @param  string  $change
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @return void
     */
    private function compete(string $change, StubDevice $device): void
    {
        $row = DB::table('stub_devices')->where('id', $device->id);

        match ($change) {
            'revoked'   => $row->update(['revoked_at' => $this->now, 'revoked_reason' => 'elsewhere']),
            'deleted'   => $row->delete(),
            'ended'     => $row->update(['idle_expires_at' => $this->now]),
            'cleared'   => $row->update(['refresh_key' => null]),
            'shortened' => $row->update(['absolute_expires_at' => $this->now->copy()->addDay()]),
            'extended'  => $row->update(['idle_expires_at' => $this->now->copy()->addDays(91)]),
            'switched'  => $this->rotateOnTheRow($device, self::ROTATION_ID, principalId: 'p-switched'),
            default     => $this->rotateOnTheRow($device, self::ROTATION_ID, '43'),
        };
    }

    /**
     * Run a competing write once, just before the exchange's compare-and-swap
     * executes, as another request that commits first would.
     *
     * @param  \Closure(): mixed  $competitor
     * @return void
     */
    private function beforeTheSwap(\Closure $competitor): void
    {
        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $competitor): void {
            if ($ran || !str_contains($query, 'refresh_rotated_at') || !str_starts_with(strtolower($query), 'update')) {
                return;
            }

            $ran = true;

            $competitor();
        });
    }

    /**
     * Expect the device's owner to be reloaded and a principal resolved for it,
     * with or without the token's principal hint, the given number of times.
     *
     * @param  int  $ownerId
     * @param  int  $times
     * @return \Tests\Unit\Stubs\StubIdentity
     */
    private function expectRefreshContext(int $ownerId, int $times = 1): StubIdentity
    {
        $identity = new StubIdentity;
        $identity->forceFill(['id' => $ownerId]);

        $this->provider->shouldReceive('retrieveById')
            ->times($times)
            ->with((string) $ownerId)
            ->andReturn($identity);

        $principal = new PlainPrincipalFixture("p-{$ownerId}");

        $this->resolver->shouldReceive('resolve')
            ->times($times)
            ->withArgs(static fn (Identity $resolved): bool => $resolved === $identity)
            ->andReturn($principal);

        return $identity;
    }

    /**
     * Record every event the exchange dispatches.
     *
     * @return void
     */
    private function recordEvents(): void
    {
        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(function (object $event): void {
                $this->dispatched[] = $event;
            });
    }

    /**
     * Assert an exchange failed, remember its failure, and return it.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh  $result
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function refused(AuthenticationFailed|ExchangedRefresh $result): AuthenticationFailed
    {
        self::assertInstanceOf(AuthenticationFailed::class, $result);

        $this->failures[] = $result;

        return $result;
    }

    /**
     * The reasons of the failures the exchanges returned.
     *
     * @return list<\SineMacula\Laravel\Authentication\Events\Enums\FailureReason>
     */
    private function failureReasons(): array
    {
        return array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures);
    }

    /**
     * Assert the device was revoked for a replay, once, with both events.
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @return void
     */
    private function assertRevokedForReuse(StubDevice $device): void
    {
        $row = $this->row($device);

        self::assertNotNull($row['revoked_at']);
        self::assertSame('rotation_reuse', $row['revoked_reason']);
        self::assertNull($row['refresh_key']);
        self::assertNull($row['previous_refresh_key']);
        self::assertSame([FailureReason::ROTATION_REUSE], $this->failureReasons());

        $revocations = array_values(array_filter($this->dispatched, static fn (object $event): bool => $event instanceof DeviceRevoked));

        self::assertCount(1, $revocations);
        self::assertSame(RevocationReason::ROTATION_REUSE, $revocations[0]->reason);
        self::assertSame($device->id, $revocations[0]->context->device?->getDeviceIdentifier());
        self::assertSame($device->id, $revocations[0]->context->deviceId);
        self::assertNull($revocations[0]->context->identity);

        foreach ([$revocations[0]->context, $this->failures[0]->context] as $context) {
            self::assertSame($device->getAttribute('authenticatable_id'), $context->identityId);
            self::assertSame(PlainPrincipalFixture::class, $context->principalMorphClass);
            self::assertSame($device->getAttribute('principal_id'), $context->principalId);
        }
    }

    /**
     * Read a device's raw row.
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @return array<string, mixed>
     */
    private function row(StubDevice $device): array
    {
        return (array) DB::table('stub_devices')->where('id', $device->id)->first();
    }

    /**
     * A refresh token for the device with the given rotation id.
     *
     * @param  \Tests\Unit\Stubs\StubDevice  $device
     * @param  string  $rotationId
     * @return string
     */
    private function tokenFor(StubDevice $device, string $rotationId): string
    {
        return $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $rotationId,
        ]);
    }

    /**
     * Decode a refresh token the exchange issued.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    private function refreshClaims(string $token): array
    {
        $claims = $this->tokens->parse($token, TokenType::REFRESH);

        self::assertIsArray($claims);

        return $claims;
    }
}
