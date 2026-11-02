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
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException;
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
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\FirstFactorRecorder;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubBareSession;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubInjectableSession;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the `RefreshTokenExchange` service that fill in the few
 * branches not covered by the JwtGuardRefreshTest's end-to-end coverage:
 *
 * - invalid `session.model` config -> refresh fails fast with an explicit
 *   configuration exception rather than falling through to `session_unknown`.
 * - resolver throws `UnresolvableIdentityException` -> the misconfiguration
 *   propagates out of the exchange instead of becoming a refresh failure.
 * - session model outside the explicit `EloquentSession` boundary is rejected.
 * - a `sid` that cannot be a key of the session model is `session_unknown`
 *   without a query, and a database error on a well-formed `sid` propagates.
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
    use InteractsWithProofs, InteractsWithSessionRecords, MockeryPHPUnitIntegration;

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

    /** @var string Issuer the test token service writes into and checks in `iss`. */
    private const string ISSUER = 'https://issuer.example.test';

    /** @var string Audience the test token service writes into and checks in `aud`. */
    private const string AUDIENCE = 'https://api.example.test';

    /** @var string IP address every exchange comes from. */
    private const string CLIENT_IP = '198.51.100.7';

    /** @var string Well-formed session id for lookups that reach the builder. */
    private const string SESSION_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /** @var \Mockery\MockInterface Identity provider mock that reloads the session owner. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface Resolver mock. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface Dispatcher mock. */
    private MockInterface $events;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationAccess Application access the exchange resolves from the container. */
    private MockInterface $access;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy Application policy the exchange resolves from the container. */
    private MockInterface $policy;

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
     * `stub_sessions` schema.
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
            self::ISSUER,
            self::AUDIENCE,
        );

        $this->context = new GuardContext(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, Request::create('/'), new CredentialTimebox(new Timebox));

        $this->policy = \Mockery::mock(ApplicationPolicy::class);
        $this->policy->shouldReceive('allowsMethod')->andReturn(true)->byDefault();
        $this->policy->shouldReceive('lifetimes')->andReturn($this->tokens->lifetimes())->byDefault();

        $this->limiter = \Mockery::mock(AttemptLimiter::class);
        $this->limiter->shouldReceive('blocked')->andReturn(null)->byDefault();
        $this->limiter->shouldReceive('recordFailure')->byDefault();

        $this->access = \Mockery::mock(ApplicationAccess::class);
        $this->access->shouldReceive('mayUse')->andReturn(true)->byDefault();

        $this->app?->instance(ApplicationPolicy::class, $this->policy);
        $this->app?->instance(ApplicationAccess::class, $this->access);
        $this->app?->instance(AttemptLimiter::class, $this->limiter);
        $this->app?->singleton(TenantAccess::class, OwnTenantOnly::class);
        $this->app?->singleton(TenantResolver::class, ResolveNoTenant::class);

        self::createSessionRecordTable('stub_sessions');
        self::migrateProofTables();

        // A session row a test saves records the first factor its sign-in would
        // have, so the tokens issued for it carry `auth_time` and `amr`.
        FirstFactorRecorder::listen(app(Dispatcher::class), static fn (): bool => true);
    }

    /**
     * Release the frozen clock and drop the in-memory schema.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_sessions');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * After the guard's context is rebound to another dispatcher, the
     * revocation of a replayed session goes to the new dispatcher and no longer
     * reaches the one the exchange was built with.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARebindOfTheContextsDispatcherRoutesLaterRevocationsToIt(): void
    {
        $session  = $this->seedRotatedSession(42, rotatedSecondsAgo: 5);
        $exchange = $this->makeExchange();

        $replacement = \Mockery::mock(Dispatcher::class);
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof SessionRevoked
                && $event->context->guard === self::GUARD_NAME
                && $event->reason         === RevocationReason::ROTATION_REUSE));

        $this->events->shouldNotReceive('dispatch');

        $this->context->rebindEvents($replacement);

        $failure = $this->refused($exchange->exchange($this->tokenFor($session, 'a-replayed-rotation-id'), self::client()));

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
        self::assertNull($failure->context->sessionId);
        self::assertNull($failure->identifier);
        self::assertNull($failure->retryAfter);
    }

    /**
     * An empty `authentication.session.model` config is now an explicit
     * configuration error rather than a silent `session_unknown` refresh
     * failure.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeThrowsWhenConfiguredSessionModelClassIsEmpty(): void
    {
        config()->set('authentication.session.model', '');

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'sid' => '01HZZZZZZZZZZZZZZZZZZZZZZZ',
            'jti' => 'rotation-id',
        ]);

        $this->expectException(InvalidSessionModelConfigurationException::class);

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

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $exchange  = $this->makeExchange();
        $exception = new UnresolvableIdentityException('cannot resolve');

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andThrow($exception);

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldNotReceive('dispatch');

        try {
            $exchange->exchange($token, self::client());
            self::fail('Expected the UnresolvableIdentityException to propagate.');
        } catch (UnresolvableIdentityException $caught) {
            self::assertSame($exception, $caught);
        }

        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $session->fresh()?->getRefreshKey());
    }

    /**
     * A principal acting within a `CanBeActive` tenant that reports inactive is
     * rejected with `tenant_inactive`, attributed to the session, and no
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

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '10',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

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
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::TENANT_INACTIVE, $failure->reason);
        self::assertSame($session->id, $failure->context->sessionId);
        self::assertSame($identity, $failure->context->identity);
        self::assertSame($principal, $failure->context->principal);
        self::assertNull($failure->context->tenant);
        self::assertSame('password', $failure->context->method);
        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $session->fresh()?->getRefreshKey());
    }

    /**
     * Provider answers for owner key `9` of a `StubIdentity` session that are
     * not that owner.
     *
     * @return iterable<string, array{0: \Closure(): mixed}>
     */
    public static function provideAnswersThatAreNotTheSessionOwner(): iterable
    {
        yield from [
            'no identity through the provider'          => [static fn (): null => null],
            'another identity model with the owner key' => [static fn (): StubPrincipal => (new StubPrincipal)->forceFill(['id' => 9])],
        ];
    }

    /**
     * The session owner is reloaded through the provider and must be that exact
     * owner: no identity, or an identity of another model that shares the owner
     * key, fails as `identity_unknown` before any principal is resolved. The
     * failure is about the session row, so it names the owner and the principal
     * the row records.
     *
     * @param  \Closure(): mixed  $answer
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideAnswersThatAreNotTheSessionOwner')]
    public function testExchangeRejectsAProviderAnswerThatIsNotTheSessionOwner(\Closure $answer): void
    {
        $plainRotationId = 'stored-rotation-id';

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME, new PlainPrincipalFixture('p-9')),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $answer());

        $this->swapSessionModelToInMemoryInstance($session);

        $exchange = $this->makeExchange();

        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldNotReceive('dispatch');

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $failure->reason);
        self::assertSame($session->id, $failure->context->sessionId);
        self::assertNull($failure->context->identity);
        self::assertSame('9', $failure->context->identityId);
        self::assertSame(PlainPrincipalFixture::class, $failure->context->principalType);
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

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '31',
            'refresh_key'          => $storedDigest,
        ])->save();

        $this->provider->shouldReceive('retrieveById')
            ->twice()
            ->with('31')
            ->andReturn($identity);

        $this->swapSessionModelToInMemoryInstance($session);

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

        $session->forceFill(['principal_type' => $failing::class, 'principal_id' => 'p-31'])->save();

        $this->resolver->shouldReceive('resolve')
            ->twice()
            ->with($identity)
            ->andReturn($failing, $working);

        $this->events->shouldNotReceive('dispatch');

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        try {
            $exchange->exchange($token, self::client());

            self::fail('The issuing failure should have propagated.');
        } catch (RandomException $exception) {
            self::assertSame('random source unavailable', $exception->getMessage());
        }

        self::assertSame($storedDigest, $this->storedDigest($session->id));

        self::assertInstanceOf(ExchangedRefresh::class, $exchange->exchange($token, self::client()));
        self::assertNotSame($storedDigest, $this->storedDigest($session->id));
    }

    /**
     * A refresh payload whose `jti` is not a string is rejected as
     * `token_invalid` and preserves the parseable session id on the emitted
     * failure event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeIncludesSessionIdWhenRotationIdShapeIsInvalid(): void
    {
        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'sid' => 'session-non-string-jti',
            'jti' => 12345,
        ]);

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::TOKEN_INVALID, $failure->reason);
        self::assertSame('session-non-string-jti', $failure->context->sessionId);
    }

    /**
     * When the refresh token carries a `principal` hint, the exchange must pass
     * that hint into the resolver and reissue follow-up tokens that preserve
     * it.
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

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '12',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $exchange = $this->makeExchange();

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->times(5)
            ->andReturn('p-12');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $session->forceFill(['principal_type' => $principal::class, 'principal_id' => 'p-12'])->save();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-12')
            ->andReturn($principal);

        $this->events->shouldNotReceive('dispatch');

        $token = $this->encodeRefreshToken([
            'principal' => 'p-12',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $result = $exchange->exchange($token, self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
        self::assertSame($identity, $result->identity);
        self::assertSame($principal, $result->principal);

        $claims = $this->tokens->parse($result->tokens->refreshToken?->reveal(), TokenType::REFRESH);

        self::assertIsArray($claims);
        self::assertSame('p-12', $claims[Claims::PRINCIPAL->value]);
    }

    /**
     * Fail-closed: a hinted principal whose identifier stringifies to `null` is
     * treated as unresolved and attributed to the session id carried by the
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

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '14',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

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
            'principal' => 'p-hinted',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $failure->reason);
        self::assertSame($session->id, $failure->context->sessionId);
    }

    /**
     * Fail-closed: when the resolver resolves nothing for a hinted `principal`,
     * the exchange reports `principal_mismatch` rather than falling through to
     * the unresolved-principal branch, and no rotation happens. Once the owner
     * is read the failure names it, and no principal: the one the session
     * records does not stand in for the one that did not resolve.
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

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME, new PlainPrincipalFixture('p-recorded')),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '15',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $exchange = $this->makeExchange();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturnNull();

        $token = $this->encodeRefreshToken([
            'principal' => 'p-hinted',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $failure->reason);
        self::assertSame($session->id, $failure->context->sessionId);
        self::assertSame('15', $failure->context->identityId);
        self::assertNull($failure->context->principalType);
        self::assertNull($failure->context->principalId);
        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $session->fresh()?->getRefreshKey());
    }

    /**
     * A refresh token without a `principal` whose identity has no default
     * principal fails as `principal_unresolved`, attributed to the session, and
     * no rotation happens.
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

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '16',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $exchange = $this->makeExchange();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturnNull();

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $failure->reason);
        self::assertSame($session->id, $failure->context->sessionId);
        self::assertSame(RefreshTokenHasher::hash($plainRotationId), $session->fresh()?->getRefreshKey());
    }

    /**
     * Rows of `[idle deadline, absolute deadline]` for sessions that have ended
     * or have no idle deadline, relative to the frozen clock in seconds.
     *
     * @return iterable<string, array{0: ?int, 1: ?int}>
     */
    public static function provideEndedSessions(): iterable
    {
        yield from [
            'idle reached'              => [0, 3600],
            'absolute reached'          => [3600, 0],
            'no idle deadline'          => [null, 3600],
            'no deadlines'              => [null, null],
            'no absolute, idle reached' => [0, null],
        ];
    }

    /**
     * A session that has ended, or that has no idle deadline, fails as
     * `session_expired` before its owner is loaded or its digest compared, and
     * nothing is written: the session is not revoked.
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

        $session = new StubSession;
        $session->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'guard'                => self::GUARD_NAME,
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
            'idle_expires_at'      => $idleIn     === null ? null : $this->now->copy()->addSeconds($idleIn),
            'absolute_expires_at'  => $absoluteIn === null ? null : $this->now->copy()->addSeconds($absoluteIn),
        ])->save();

        $this->swapSessionModelToInMemoryInstance($session);

        $before = (array) DB::table('stub_sessions')->where('id', $session->id)->first();

        $this->provider->shouldNotReceive('retrieveById');
        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldNotReceive('dispatch');

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $failure = $this->refused($this->makeExchange()->exchange($token, self::client()));

        self::assertSame(FailureReason::SESSION_EXPIRED, $failure->reason);
        self::assertSame($session->id, $failure->context->sessionId);
        self::assertSame($before, (array) DB::table('stub_sessions')->where('id', $session->id)->first());
    }

    /**
     * A current rotation id is rotated to its successor: the row records the
     * presented id as the previous one and the exchange's time as the rotation
     * time, moves the idle deadline to the idle lifetime from that time, and
     * leaves the absolute deadline alone. The new refresh token carries the
     * successor, and the returned session mirrors the row with nothing left to
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
        $session  = $this->seedSession(32, [
            'refresh_key'         => RefreshTokenHasher::hash(self::ROTATION_ID),
            'idle_expires_at'     => $this->now->copy()->addMinute(),
            'absolute_expires_at' => $absolute,
        ]);

        $this->expectRefreshContext(32);
        $this->recordEvents();

        $result = $this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);

        $successor    = RefreshTokenHasher::successor(self::ROTATION_ID);
        $expectedIdle = $this->now->getTimestamp() + (self::REFRESH_TTL * 60);
        $stored       = StubSession::query()->findOrFail($session->id);

        self::assertSame(RefreshTokenHasher::hash($successor), $stored->refresh_key);
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $stored->previous_refresh_key);
        self::assertSame($this->now->getTimestamp(), $stored->refresh_rotated_at?->getTimestamp());
        self::assertSame($expectedIdle, $stored->idle_expires_at?->getTimestamp());
        self::assertSame($absolute->getTimestamp(), $stored->absolute_expires_at?->getTimestamp());
        self::assertSame($successor, $this->refreshClaims($result->tokens->refreshToken?->reveal())[Claims::JWT_ID->value]);
        self::assertSame($expectedIdle, $this->refreshClaims($result->tokens->refreshToken?->reveal())[Claims::EXPIRES_AT->value]);
        self::assertSame($stored->refresh_key, $result->record->getRefreshKey());
        self::assertSame($stored->previous_refresh_key, $result->record->getPreviousRefreshKey());
        self::assertSame($expectedIdle, $result->record->getIdleExpiresAt()?->getTimestamp());
        self::assertFalse($result->record->isDirty());
        self::assertSame([], $this->dispatched);
    }

    /**
     * Refreshing a session with no absolute deadline rotates it with the same
     * compare-and-swap, matching the absent deadline as such, moves its idle
     * deadline the full idle lifetime, and adds no absolute deadline.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeRotatesASessionWithoutAnAbsoluteDeadline(): void
    {
        $session = $this->seedSession(32, [
            'refresh_key'         => RefreshTokenHasher::hash(self::ROTATION_ID),
            'idle_expires_at'     => $this->now->copy()->addMinute(),
            'absolute_expires_at' => null,
        ]);

        $this->expectRefreshContext(32);
        $this->recordEvents();

        $result = $this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);

        $expectedIdle = $this->now->getTimestamp() + (self::REFRESH_TTL * 60);
        $stored       = StubSession::query()->findOrFail($session->id);

        self::assertSame(RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)), $stored->refresh_key);
        self::assertSame($expectedIdle, $stored->idle_expires_at?->getTimestamp());
        self::assertNull($stored->absolute_expires_at);
        self::assertNull($result->record->getAbsoluteExpiresAt());
        self::assertSame($expectedIdle, $this->refreshClaims($result->tokens->refreshToken?->reveal())[Claims::EXPIRES_AT->value]);
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
        $session = $this->seedRotatedSession(33, rotatedSecondsAgo: 29, idle: $idle);
        $before  = $this->row($session);

        $this->expectRefreshContext(33);
        $this->recordEvents();

        $result = $this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
        self::assertSame($current, $this->refreshClaims($result->tokens->refreshToken?->reveal())[Claims::JWT_ID->value]);
        self::assertSame($idle->getTimestamp(), $this->refreshClaims($result->tokens->refreshToken?->reveal())[Claims::EXPIRES_AT->value]);
        self::assertSame($before, $this->row($session));
        self::assertSame([], $this->dispatched);
    }

    /**
     * The grace window and its leeway are always the guard's token service's,
     * whatever lifetimes the application policy returns: under a policy that
     * disables grace, the previous rotation id inside the service's window
     * still gets the current credential, and under one that widens it to the
     * most allowed, the previous id past the service's window still proves a
     * replay.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testTheGraceWindowIsTheTokenServicesWhateverLifetimesThePolicyReturns(): void
    {
        $policyGrace = new \ArrayObject(['seconds' => 0]);
        $retried     = $this->seedRotatedSession(35, rotatedSecondsAgo: self::GRACE - 1);

        $this->policy->shouldReceive('lifetimes')->andReturnUsing(
            static fn (): TokenLifetimes => new TokenLifetimes(self::ACCESS_TTL, self::REFRESH_TTL, 60 * 24 * 180, $policyGrace['seconds']),
        );

        $this->expectRefreshContext(35);

        $result = $this->makeExchange()->exchange($this->tokenFor($retried, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
        self::assertSame(RefreshTokenHasher::successor(self::ROTATION_ID), $this->refreshClaims($result->tokens->refreshToken?->reveal())[Claims::JWT_ID->value]);

        $policyGrace['seconds'] = TokenLifetimes::MAX_GRACE_SECONDS;

        $replayed = $this->seedRotatedSession(36, rotatedSecondsAgo: self::GRACE);

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($replayed, self::ROTATION_ID), self::client()));

        $this->assertRevokedForReuse($replayed);
    }

    /**
     * Rows of `[how the presented rotation id relates to the session, seconds
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
            'an id the session never issued'          => ['foreign', 5, 30],
            'previous digest without a rotation time' => ['no rotation time', 5, 30],
            'rotation time without a previous digest' => ['no previous digest', 5, 30],
        ];
    }

    /**
     * A validly signed token for a live session whose rotation id is neither
     * the current one nor the previous one inside the grace window proves the
     * token was replayed: the session is revoked with reason `rotation_reuse`
     * (its time and reason recorded, both digests cleared), `SessionRevoked`
     * and `AuthenticationFailed` are dispatched, and nothing is issued.
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
    public function testReplayRevokesTheSession(string $presented, int $rotatedSecondsAgo, int $grace): void
    {
        $session = $this->seedRotatedSession(34, rotatedSecondsAgo: $rotatedSecondsAgo);

        $changes = match ($presented) {
            'unrelated'          => ['refresh_key' => RefreshTokenHasher::hash('set-outside-a-rotation')],
            'no rotation time'   => ['refresh_rotated_at' => null],
            'no previous digest' => ['previous_refresh_key' => null],
            default              => [],
        };

        DB::table('stub_sessions')->where('id', $session->id)->update([...$changes, 'updated_at' => $this->now]);

        $rotationId = match ($presented) {
            'older'   => 'the-id-before-the-previous-one',
            'foreign' => 'never-issued-rotation-id',
            default   => self::ROTATION_ID,
        };

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $this->refused($this->makeExchange($grace)->exchange($this->tokenFor($session, $rotationId), self::client()));

        $this->assertRevokedForReuse($session);
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
    public function testOnlyTheImmediatelyPreviousRotationIdIsHonored(): void
    {
        $first   = self::ROTATION_ID;
        $session = $this->seedSession(35, ['refresh_key' => RefreshTokenHasher::hash($first)]);

        $this->expectRefreshContext(35, 2);
        $this->recordEvents();

        $second = $this->makeExchange()->exchange($this->tokenFor($session, $first), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $second);

        $third = $this->makeExchange()->exchange($second->tokens->refreshToken?->reveal(), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $third);
        $this->refused($this->makeExchange()->exchange($this->tokenFor($session, $first), self::client()));

        $this->assertRevokedForReuse($session);
    }

    /**
     * A session that holds no refresh credential cannot tell a replay from
     * anything else, so its tokens are rejected as `refresh_key_missing`
     * without revoking it or writing anything.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testSessionWithoutARefreshCredentialIsRejectedWithoutRevoking(): void
    {
        $session = $this->seedSession(36, ['refresh_key' => null, 'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $before  = $this->row($session);

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client()));
        self::assertSame($before, $this->row($session));
        self::assertSame([FailureReason::REFRESH_KEY_MISSING], $this->failureReasons());
    }

    /**
     * A refresh for a principal the session no longer records (the session was
     * switched to another one) fails as `session_principal_mismatch`, without
     * revoking the session or writing to it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARefreshAsAPrincipalTheSessionNoLongerRecordsIsRefused(): void
    {
        $session = $this->seedSession(44, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID), 'principal_id' => 'p-switched']);
        $before  = $this->row($session);

        $this->expectRefreshContext(44);
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client()));
        self::assertSame([FailureReason::SESSION_PRINCIPAL_MISMATCH], $this->failureReasons());
        self::assertSame($before, $this->row($session));
    }

    /**
     * A session that holds no refresh credential and has ended fails as
     * `session_expired`, not `refresh_key_missing`: the session is judged
     * before the credential, and nothing is written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testEndedSessionIsReportedBeforeAMissingRefreshCredential(): void
    {
        $session = $this->seedSession(36, ['refresh_key' => null, 'idle_expires_at' => $this->now]);
        $before  = $this->row($session);

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client()));
        self::assertSame($before, $this->row($session));
        self::assertSame([FailureReason::SESSION_EXPIRED], $this->failureReasons());
    }

    /**
     * A session loaded without its previous digest cannot be judged for a token
     * that is not current: the missing column is reported instead of the token
     * being read as a replay that revokes the session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testSessionLoadedWithoutItsPreviousDigestIsReportedNotRevoked(): void
    {
        $session = $this->seedRotatedSession(37, rotatedSecondsAgo: 5);

        $loaded = new StubSession;
        $loaded->setRawAttributes(array_diff_key((array) DB::table('stub_sessions')->where('id', $session->id)->first(), ['previous_refresh_key' => true]), true);
        $loaded->exists = true;

        $this->swapSessionModelToInMemoryInstance($loaded, false);

        $this->events->shouldNotReceive('dispatch');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `previous_refresh_key` attribute is not loaded');

        $this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client());
    }

    /**
     * Revoking a session records the time and reason, clears both digests,
     * mirrors the revocation on the in-memory session, and dispatches
     * `SessionRevoked` once. Revoking it again changes nothing: the first
     * revocation's time and reason are kept and no event is dispatched.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRevokingASessionIsIdempotent(): void
    {
        $session = $this->seedRotatedSession(38, rotatedSecondsAgo: 5);

        $this->recordEvents();

        self::assertTrue($this->makeExchange()->revokeSession($session, RevocationReason::ROTATION_REUSE, self::client()));
        self::assertSame($this->now->getTimestamp(), $session->revoked_at?->getTimestamp());
        self::assertSame('rotation_reuse', $session->getRevokedReason());
        self::assertNull($session->getRefreshKey());
        self::assertFalse($session->isDirty());

        $first = $this->row($session);

        Carbon::setTestNow($this->now->copy()->addMinute());

        self::assertFalse($this->makeExchange()->revokeSession(StubSession::query()->findOrFail($session->id), RevocationReason::ROTATION_REUSE, self::client()));
        self::assertSame($first, $this->row($session));
        self::assertCount(1, $this->dispatched);
        self::assertInstanceOf(SessionRevoked::class, $this->dispatched[0]);
        self::assertSame($session, $this->dispatched[0]->context->session);
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
        $session = $this->seedSession(39, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(39);
        $this->recordEvents();
        $this->beforeTheSwap(fn () => $this->rotateOnTheRow($session, self::ROTATION_ID));

        $result = $this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
        self::assertSame(RefreshTokenHasher::successor(self::ROTATION_ID), $this->refreshClaims($result->tokens->refreshToken?->reveal())[Claims::JWT_ID->value]);
        self::assertSame(RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)), $this->storedDigest($session->id));
        self::assertSame($result->record->getRefreshKey(), $this->storedDigest($session->id));
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
        $session = $this->seedSession(40, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(40);
        $this->recordEvents();
        $this->beforeTheSwap(function () use ($session): void {
            $this->rotateOnTheRow($session, self::ROTATION_ID);

            Carbon::setTestNow($this->now->copy()->addMinutes(5));
        });

        self::assertInstanceOf(ExchangedRefresh::class, $this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client()));
        self::assertSame([], $this->dispatched);
    }

    /**
     * With grace disabled, a parallel refresh that rotates first leaves the
     * loser holding a replaced token: the row judged again proves a replay, and
     * the session is revoked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testLostRotationWithGraceDisabledRevokesTheSession(): void
    {
        $session = $this->seedSession(41, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(41);
        $this->recordEvents();
        $this->beforeTheSwap(fn () => $this->rotateOnTheRow($session, self::ROTATION_ID));

        $this->refused($this->makeExchange(0)->exchange($this->tokenFor($session, self::ROTATION_ID), self::client()));

        $this->assertRevokedForReuse($session);
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
            'revoked'                  => ['revoked', FailureReason::SESSION_REVOKED],
            'deleted'                  => ['deleted', FailureReason::SESSION_UNKNOWN],
            'ended'                    => ['ended', FailureReason::SESSION_EXPIRED],
            'credential cleared'       => ['cleared', FailureReason::REFRESH_KEY_MISSING],
            'absolute deadline moved'  => ['shortened', FailureReason::ROTATION_CONFLICT],
            'idle deadline moved'      => ['extended', FailureReason::ROTATION_CONFLICT],
            'rotated to another owner' => ['reowned', FailureReason::IDENTITY_UNKNOWN],
            'switched to another one'  => ['switched', FailureReason::SESSION_PRINCIPAL_MISMATCH],
        ];
    }

    /**
     * When the swap misses for any other reason, the row judged again decides
     * the failure: a session revoked, deleted, ended, or stripped of its
     * credential in between fails for that reason; a token that is still
     * current, because only a deadline moved, fails as `rotation_conflict`; and
     * a grace retry whose row now has another owner fails as
     * `identity_unknown`, or, when the row now records another principal,
     * `session_principal_mismatch`. None of them revokes the session, and the
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
        $session = $this->seedSession(42, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(42);
        $this->recordEvents();

        $swaps = 0;

        DB::connection()->listen(static function (QueryExecuted $query) use (&$swaps): void {
            $swaps += str_contains($query->sql, 'refresh_rotated_at') && str_contains($query->sql, 'is null') ? 1 : 0;
        });

        $this->beforeTheSwap(fn () => $this->compete($change, $session));

        $this->refused($this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client()));
        self::assertSame([$reason], $this->failureReasons());
        self::assertSame(1, $swaps);
        self::assertNotContains(SessionRevoked::class, array_map(static fn (object $event): string => $event::class, $this->dispatched));
        self::assertNotSame('rotation_reuse', $this->row($session)['revoked_reason'] ?? null);
    }

    /**
     * A `sid` that cannot be a key of the configured session model names no
     * session: the exchange reports `session_unknown` without querying.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeRejectsMalformedSessionIdWithoutQuerying(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldNotReceive('find');

        StubInjectableSession::$injectedBuilder = $builder;

        config()->set('authentication.session.model', StubInjectableSession::class);

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'sid' => 'not-a-valid-uuid',
            'jti' => 'rotation-id',
        ]);

        $this->events->shouldNotReceive('dispatch');

        $failure = $this->refused($exchange->exchange($token, self::client()));

        self::assertSame(FailureReason::SESSION_UNKNOWN, $failure->reason);
        self::assertSame('not-a-valid-uuid', $failure->context->sessionId);
    }

    /**
     * A database error on a well-formed `sid` propagates to the caller as a
     * server error instead of being reported as an unknown session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangePropagatesQueryExceptionDuringSessionLookup(): void
    {
        $failure = new QueryException('testing', 'select', [], new \PDOException('server has gone away'));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('find')
            ->once()
            ->with(self::SESSION_ID)
            ->andThrow($failure);

        StubInjectableSession::$injectedBuilder = $builder;

        config()->set('authentication.session.model', StubInjectableSession::class);

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'sid' => self::SESSION_ID,
            'jti' => 'rotation-id',
        ]);

        $this->events->shouldNotReceive('dispatch');

        $this->expectExceptionObject($failure);

        $exchange->exchange($token, self::client());
    }

    /**
     * The exchange rejects configured session models that implement the generic
     * `Session` contract but do not satisfy the explicit `EloquentSession`
     * persistence boundary.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testExchangeThrowsWhenConfiguredSessionModelDoesNotImplementEloquentSession(): void
    {
        config()->set('authentication.session.model', StubBareSession::class);

        $exchange = $this->makeExchange();

        $token = $this->encodeRefreshToken([
            'sid' => 'bare-session-1',
            'jti' => 'rotation-id',
        ]);

        $this->expectException(InvalidSessionModelConfigurationException::class);
        $this->expectExceptionMessage(StubBareSession::class);

        $exchange->exchange($token, self::client());
    }

    /**
     * Once failed refreshes fill a limit, the exchange stops before looking the
     * session up: it reports and returns `rate_limited` with the wait, and
     * counts nothing more. The limits are asked about the token's session and
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
                && $subject->identifier                                                      === self::SESSION_ID
                && $subject->identifierType                                                  === null
                && $subject->ip                                                              === self::CLIENT_IP))
            ->andReturn(42);
        $this->limiter->shouldNotReceive('recordFailure');
        $this->provider->shouldNotReceive('retrieveById');

        $this->recordEvents();

        DB::connection()->enableQueryLog();

        $failure = $this->makeExchange()->exchange($this->encodeRefreshToken(['sid' => self::SESSION_ID, 'jti' => self::ROTATION_ID]), self::client());

        self::assertSame([], DB::connection()->getQueryLog());
        self::assertSame([], $this->dispatched);
        self::assertInstanceOf(AuthenticationFailed::class, $failure);
        self::assertSame(self::GUARD_NAME, $failure->context->guard);
        self::assertSame(FailureReason::RATE_LIMITED, $failure->reason);
        self::assertSame(self::SESSION_ID, $failure->context->sessionId);
        self::assertSame(42, $failure->retryAfter);
    }

    /**
     * Every failure is counted against the token's session and the client's IP
     * address before it is reported; a token that does not parse names no
     * session, so it counts against the IP address only.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testEveryFailureIsCountedAgainstTheSessionAndTheIpAddress(): void
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

        $unknown = $this->encodeRefreshToken(['sid' => self::SESSION_ID, 'jti' => self::ROTATION_ID]);

        $this->refused($this->makeExchange()->exchange($unknown, self::client()));

        $this->failures = [];

        $this->refused($this->makeExchange()->exchange('not-a-jwt', self::client()));
        self::assertSame([self::SESSION_ID, null], $counted);
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
        $session = $this->seedSession(41, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(41);
        $this->limiter->shouldNotReceive('recordFailure');

        self::assertInstanceOf(ExchangedRefresh::class, $this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client()));
    }

    /**
     * Rows of `[guard]` a session may record other than the exchanging guard.
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
     * A session of another guard, or of none, fails as `session_guard_mismatch`
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
    public function testASessionOfAnotherGuardIsRefusedWithoutRevokingIt(?string $guard): void
    {
        $session = $this->seedSession(42, ['guard' => $guard, 'refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $before  = $this->row($session);

        $this->provider->shouldNotReceive('retrieveById');
        $this->recordEvents();

        $failure = $this->refused($this->makeExchange()->exchange($this->tokenFor($session, 'a-replayed-rotation-id'), self::client()));

        self::assertSame([FailureReason::SESSION_GUARD_MISMATCH], $this->failureReasons());
        self::assertSame([], $this->dispatched);
        self::assertSame(self::GUARD_NAME, $failure->context->guard);
        self::assertSame($session->id, $failure->context->session?->getSessionIdentifier());
        self::assertSame($session->id, $failure->context->sessionId);
        self::assertSame($before, $this->row($session));
    }

    /**
     * The method that started the session must still be one the guard lets
     * start its sessions; a session that records no method fails closed without
     * asking. Neither writes anything.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testTheMethodThatStartedTheSessionMustStillBeAllowed(): void
    {
        $removed  = $this->seedSession(43, ['sign_in_method' => 'sso', 'refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $unstated = $this->seedSession(43, ['sign_in_method' => null, 'refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $before   = [$this->row($removed), $this->row($unstated)];

        $this->policy->shouldReceive('allowsMethod')->once()->with(self::GUARD_NAME, 'sso')->andReturn(false);
        $this->access->shouldNotReceive('mayUse');
        $this->expectRefreshContext(43, 2);
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($removed, self::ROTATION_ID), self::client()));
        $this->refused($this->makeExchange()->exchange($this->tokenFor($unstated, self::ROTATION_ID), self::client()));
        self::assertSame([FailureReason::METHOD_NOT_ALLOWED, FailureReason::METHOD_NOT_ALLOWED], $this->failureReasons());
        self::assertSame($before, [$this->row($removed), $this->row($unstated)]);
    }

    /**
     * `ApplicationAccess` must still let the principal use the application;
     * when it does not, the exchange fails as `principal_ineligible` without
     * writing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testTheAccessMustStillLetThePrincipalUseTheApplication(): void
    {
        $session = $this->seedSession(44, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);
        $before  = $this->row($session);

        $this->expectRefreshContext(44);

        $this->policy->shouldReceive('allowsMethod')->once()->with(self::GUARD_NAME, 'password')->andReturn(true);
        $this->access->shouldReceive('mayUse')
            ->once()
            ->with(self::GUARD_NAME, \Mockery::type(Principal::class))
            ->andReturn(false);
        $this->recordEvents();

        $this->refused($this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client()));
        self::assertSame([FailureReason::PRINCIPAL_INELIGIBLE], $this->failureReasons());
        self::assertSame($before, $this->row($session));
    }

    /**
     * A rotation moves the idle deadline by the idle lifetime the policy gives
     * the guard, not the token service's own.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARotationMovesTheIdleDeadlineByThePolicysLifetimes(): void
    {
        $session = $this->seedSession(45, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)]);

        $this->expectRefreshContext(45);
        $this->policy->shouldReceive('lifetimes')
            ->once()
            ->with(self::GUARD_NAME)
            ->andReturn(new TokenLifetimes(self::ACCESS_TTL, 45, 60 * 24 * 180, self::GRACE));

        $result = $this->makeExchange()->exchange($this->tokenFor($session, self::ROTATION_ID), self::client());

        self::assertInstanceOf(ExchangedRefresh::class, $result);
        self::assertSame($this->now->getTimestamp() + (45 * 60), StubSession::query()->findOrFail($session->id)->idle_expires_at?->getTimestamp());
        self::assertSame($this->now->getTimestamp() + (45 * 60), $this->refreshClaims($result->tokens->refreshToken?->reveal())[Claims::EXPIRES_AT->value]);
    }

    /**
     * Define the test environment: in-memory sqlite + stub session model +
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

        $config->set('authentication.session.model', StubSession::class);
        $config->set('authentication.session.table', 'stub_sessions');
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
                self::ISSUER,
                self::AUDIENCE,
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
     * Encode a refresh-token-style JWT with `iat`, `exp`, the test issuer,
     * audience and guard, under the `refresh+jwt` header type.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encodeRefreshToken(array $claims): string
    {
        $now = $this->now->getTimestamp();

        return JWT::encode([
            ...$claims,
            'iss'       => self::ISSUER,
            'aud'       => self::AUDIENCE,
            'client_id' => self::GUARD_NAME,
            'iat'       => $now,
            'exp'       => $now + (self::REFRESH_TTL * 60),
        ], self::SECRET, self::ALGORITHM, self::KID, ['typ' => TokenType::REFRESH->value]);
    }

    /**
     * Swap the configured session model so the exchange resolves the supplied
     * in-memory session through `find()` instead of issuing a real polymorphic
     * query. The session is reloaded first, unless told otherwise, so it
     * carries every column, as the exchange's own lookup would.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @param  bool  $reload
     * @return void
     */
    private function swapSessionModelToInMemoryInstance(StubSession $session, bool $reload = true): void
    {
        if ($reload) {
            $session->refresh();
        }

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->atLeast()->once()
            ->andReturnSelf();
        $builder->shouldReceive('find')
            ->with($session->id)
            ->andReturn($session);
        $builder->shouldReceive('find')
            ->andReturn(null);

        StubInjectableSession::$injectedBuilder = $builder;

        config()->set('authentication.session.model', StubInjectableSession::class);
    }

    /**
     * Expect the exchange's identity provider to reload the session's owner
     * once, by the owner key stored on the session row, and answer with the
     * supplied identity.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @param  mixed  $identity
     * @return void
     */
    private function expectOwnerReload(StubSession $session, mixed $identity): void
    {
        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with($session->getAttribute('authenticatable_id'))
            ->andReturn($identity);
    }

    /**
     * Read the refresh digest stored on the session row.
     *
     * @param  string  $sessionId
     * @return mixed
     */
    private function storedDigest(string $sessionId): mixed
    {
        return DB::table('stub_sessions')->where('id', $sessionId)->value('refresh_key');
    }

    /**
     * Persist a live session owned by the `StubIdentity` with the given key,
     * with any further state.
     *
     * @param  int  $ownerId
     * @param  array<string, mixed>  $state
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function seedSession(int $ownerId, array $state): StubSession
    {
        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME, new PlainPrincipalFixture("p-{$ownerId}")),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => (string) $ownerId,
            ...$state,
        ])->save();

        return StubSession::query()->findOrFail($session->id);
    }

    /**
     * Persist a live session that was rotated from `ROTATION_ID` to its
     * successor the given number of seconds ago.
     *
     * @param  int  $ownerId
     * @param  int  $rotatedSecondsAgo
     * @param  ?\Carbon\Carbon  $idle
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function seedRotatedSession(int $ownerId, int $rotatedSecondsAgo, ?Carbon $idle = null): StubSession
    {
        return $this->seedSession($ownerId, [
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)),
            'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID),
            'refresh_rotated_at'   => $this->now->copy()->subSeconds($rotatedSecondsAgo),
            'idle_expires_at'      => $idle ?? $this->now->copy()->addDays(30),
        ]);
    }

    /**
     * Rotate the session's row from the given rotation id to its successor, as
     * a refresh that won a race would, optionally moving it to another owner,
     * or to another principal as a switch that won would.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @param  string  $rotationId
     * @param  ?string  $ownerId
     * @param  ?string  $principalId
     * @return void
     */
    private function rotateOnTheRow(StubSession $session, string $rotationId, ?string $ownerId = null, ?string $principalId = null): void
    {
        DB::table('stub_sessions')->where('id', $session->id)->update([
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor($rotationId)),
            'previous_refresh_key' => RefreshTokenHasher::hash($rotationId),
            'refresh_rotated_at'   => $this->now,
            'authenticatable_id'   => $ownerId     ?? $session->getAttribute('authenticatable_id'),
            'principal_id'         => $principalId ?? $session->getAttribute('principal_id'),
        ]);
    }

    /**
     * Commit the named competing change to the session's row.
     *
     * @param  string  $change
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return void
     */
    private function compete(string $change, StubSession $session): void
    {
        $row = DB::table('stub_sessions')->where('id', $session->id);

        match ($change) {
            'revoked'   => $row->update(['revoked_at' => $this->now, 'revoked_reason' => 'elsewhere']),
            'deleted'   => $row->delete(),
            'ended'     => $row->update(['idle_expires_at' => $this->now]),
            'cleared'   => $row->update(['refresh_key' => null]),
            'shortened' => $row->update(['absolute_expires_at' => $this->now->copy()->addDay()]),
            'extended'  => $row->update(['idle_expires_at' => $this->now->copy()->addDays(91)]),
            'switched'  => $this->rotateOnTheRow($session, self::ROTATION_ID, principalId: 'p-switched'),
            default     => $this->rotateOnTheRow($session, self::ROTATION_ID, '43'),
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
     * Expect the session's owner to be reloaded and a principal resolved for
     * it, with or without the token's principal hint, the given number of
     * times.
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
     * Assert the session was revoked for a replay, once, with both events.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return void
     */
    private function assertRevokedForReuse(StubSession $session): void
    {
        $row = $this->row($session);

        self::assertNotNull($row['revoked_at']);
        self::assertSame('rotation_reuse', $row['revoked_reason']);
        self::assertNull($row['refresh_key']);
        self::assertNull($row['previous_refresh_key']);
        self::assertSame([FailureReason::ROTATION_REUSE], $this->failureReasons());

        $revocations = array_values(array_filter($this->dispatched, static fn (object $event): bool => $event instanceof SessionRevoked));

        self::assertCount(1, $revocations);
        self::assertSame(RevocationReason::ROTATION_REUSE, $revocations[0]->reason);
        self::assertSame($session->id, $revocations[0]->context->session?->getSessionIdentifier());
        self::assertSame($session->id, $revocations[0]->context->sessionId);
        self::assertNull($revocations[0]->context->identity);

        foreach ([$revocations[0]->context, $this->failures[0]->context] as $context) {
            self::assertSame($session->getAttribute('authenticatable_id'), $context->identityId);
            self::assertSame(PlainPrincipalFixture::class, $context->principalType);
            self::assertSame($session->getAttribute('principal_id'), $context->principalId);
        }
    }

    /**
     * Read a session's raw row.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return array<string, mixed>
     */
    private function row(StubSession $session): array
    {
        return (array) DB::table('stub_sessions')->where('id', $session->id)->first();
    }

    /**
     * A refresh token for the session with the given rotation id.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @param  string  $rotationId
     * @return string
     */
    private function tokenFor(StubSession $session, string $rotationId): string
    {
        return $this->encodeRefreshToken([
            'sid' => $session->id,
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
