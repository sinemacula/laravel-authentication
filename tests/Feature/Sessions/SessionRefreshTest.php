<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RefreshesSessions;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\InspectsIssuanceGuards;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\TestCase;

/**
 * Feature tests of refreshing a session through the session service, from the
 * request and from plain values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRefresh::class)]
#[CoversClass(RefreshResult::class)]
#[CoversClass(SessionService::class)]
#[CoversTrait(RefreshesSessions::class)]
#[CoversTrait(HoldsARotatedSession::class)]
final class SessionRefreshTest extends TestCase
{
    use InspectsIssuanceGuards, InteractsWithSessions;

    /** @var string The cookie application, over the same identities. */
    private const string BROWSER = 'admin';

    /** @var string The cookie application's refresh cookie. */
    private const string COOKIE = '__Secure-admin_refresh_token';

    /** @var list<class-string> Every event a refresh dispatches. */
    private const array EVENTS = [
        Attempting::class,
        Refreshed::class,
        SignedIn::class,
        Validated::class,
        Login::class,
        Authenticated::class,
        PrincipalAssigned::class,
        SessionAuthenticated::class,
        Failed::class,
        AuthenticationFailed::class,
    ];

    /** @var list<class-string> The events of a refresh, in order, inside a transaction or outside one. */
    private const array REFRESHED = [
        Attempting::class,
        Refreshed::class,
        SignedIn::class,
        Validated::class,
        Login::class,
        Authenticated::class,
        PrincipalAssigned::class,
        SessionAuthenticated::class,
    ];

    /** @var list<class-string> The events of a refused refresh, in order. */
    private const array REFUSAL = [Attempting::class, Failed::class, AuthenticationFailed::class];

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A refresh rotates the session, reports the rotation and then binds the
     * guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshRotatesTheSessionAndBindsTheGuardToIt(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $before   = $this->refreshKeyOf($session);
        $guard    = $this->freshGuard();

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($guard)->refresh(self::bodyToken($session->tokens), self::requestClient());

        self::assertTrue($result->isRefreshed());
        self::assertFalse($result->isFailed());
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertSame(RefreshTokenSource::BODY, $result->source);

        $refreshed = $result->session;

        self::assertInstanceOf(SignedInSession::class, $refreshed);
        self::assertIsModel($identity, $refreshed->identity);
        self::assertSame($session->record->getKey(), $refreshed->record->getKey());
        self::assertSame('password', $refreshed->method);
        self::assertNotSame($before, $this->refreshKeyOf($session));

        $rotation = $this->claimsOf(self::bodyRefreshToken($refreshed->tokens))[Claims::JWT_ID->value] ?? null;

        self::assertIsString($rotation);
        self::assertSame($this->refreshKeyOf($session), RefreshTokenHasher::hash($rotation));
        self::assertSame($session->record->getKey(), $this->claimsOf($refreshed->tokens->accessToken->reveal(), TokenType::ACCESS)[Claims::SESSION_ID->value] ?? null);

        self::assertSame(self::REFRESHED, $this->recordedClasses());

        $attempting = $this->recordedEvent(Attempting::class);
        $signedIn   = $this->recordedEvent(SignedIn::class);

        self::assertSame(['api', [], false], [$attempting->guard, $attempting->credentials, $attempting->remember]);
        EventContextAssertions::assertSession($refreshed->record, $this->recordedEvent(Refreshed::class)->context);
        self::assertSame(self::CLIENT_IP, $this->recordedEvent(Refreshed::class)->context->client->ip);
        self::assertTrue($signedIn->refresh);
        self::assertSame('password', $signedIn->context->method);
        self::assertSame($refreshed->identity, $this->recordedEvent(Validated::class)->user);
        self::assertSame($refreshed->identity, $this->recordedEvent(Login::class)->user);
        self::assertFalse($this->recordedEvent(Login::class)->remember);

        self::assertSame($refreshed->identity, $guard->user());
        self::assertSame($refreshed->principal, $guard->principal());
        self::assertSame($refreshed->record, $guard->session());
    }

    /**
     * The refresh token a sign-in returned is taken as the `Secret` it was
     * returned as, as its revealed string is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshTakesTheTokenAsTheSecretItWasReturnedAs(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $token   = $session->tokens->refreshToken;

        self::assertNotNull($token);

        $result = self::sessionsOf($this->freshGuard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient());

        self::assertTrue($result->isRefreshed());
        self::assertSame($session->record->getKey(), $result->session?->record->getKey());
    }

    /**
     * The bind events carry the tenant and method the refresh established.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBindReportsTheTenantAndMethodTheRefreshEstablished(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn('members', 'member@example.test');
        $guard   = $this->freshGuard('members');

        $this->recordEvents([Refreshed::class, PrincipalAssigned::class, SessionAuthenticated::class]);

        self::assertTrue(self::sessionsOf($guard)->refresh(self::bodyToken($session->tokens), self::requestClient())->isRefreshed());

        foreach ($this->recorded as $event) {

            self::assertInstanceOf(AuthenticationEvent::class, $event);

            $context = $event->context();

            EventContextAssertions::assertTenant($tenant, $context);
            EventContextAssertions::assertPrincipal($membership, $context);
            self::assertSame('password', $context->method);
        }

        self::assertCount(3, $this->recorded);
        self::assertIsModel($tenant, $guard->tenant());
    }

    /**
     * Every refusal is returned with its reason after the failure events, and
     * binds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryRefusalIsReturnedWithItsReason(): void
    {
        $this->seedIdentity();

        $replayed = $this->signedIn();
        $unknown  = $this->signedIn();
        $revoked  = $this->signedIn();

        self::assertTrue(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($replayed->tokens), self::requestClient())->isRefreshed(),
        );

        Session::query()->whereKey($unknown->record->getKey())->delete();
        Session::query()->whereKey($revoked->record->getKey())->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'signed_out']);

        $this->moveTo(CarbonImmutable::now()->addMinute());

        $cases = [
            'not-a-token'                              => FailureReason::TOKEN_INVALID,
            $unknown->tokens->refreshToken?->reveal()  => FailureReason::SESSION_UNKNOWN,
            $revoked->tokens->refreshToken?->reveal()  => FailureReason::SESSION_REVOKED,
            $replayed->tokens->refreshToken?->reveal() => FailureReason::ROTATION_REUSE,
        ];

        foreach ($cases as $token => $reason) {

            $guard = $this->freshGuard();

            $this->recordEvents(self::EVENTS);

            $result = self::sessionsOf($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient());

            self::assertTrue($result->isFailed(), $reason->value);
            self::assertFalse($result->isRefreshed());
            self::assertNull($result->session);
            self::assertSame($reason, $result->reason);
            self::assertNull($result->retryAfter);
            self::assertSame(RefreshTokenSource::BODY, $result->source);
            self::assertSame(self::REFUSAL, $this->recordedClasses(), $reason->value);

            $failed  = $this->recordedEvent(Failed::class);
            $failure = $this->recordedEvent(AuthenticationFailed::class);

            self::assertSame(['api', null, []], [$failed->guard, $failed->user, $failed->credentials]);
            self::assertSame([AuthenticationFlow::REFRESH, $reason], [$failure->flow, $failure->reason]);
            self::assertTrue($guard->guest());
        }
    }

    /**
     * A rate-limited refresh is returned as `rate_limited` with its wait
     * instead of thrown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedRefreshIsReturnedWithItsWait(): void
    {
        config()->set('authentication.rate_limits.refresh.per_ip.max', 1);

        self::assertSame(
            FailureReason::TOKEN_INVALID,
            self::sessionsOf($this->freshGuard())->refresh(PresentedRefreshToken::fromBody('not-a-token'), self::requestClient())->reason,
        );

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($this->freshGuard())->refresh(PresentedRefreshToken::fromBody('not-a-token'), self::requestClient());

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertSame(60, $result->retryAfter);
        self::assertSame(self::REFUSAL, $this->recordedClasses());
        self::assertSame(60, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
    }

    /**
     * A refresh read from the request says where its token came from, the body
     * or a header, whether it was refreshed or refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshFromTheRequestSaysWhereItsTokenWasRead(): void
    {
        $this->seedIdentity();

        $fromHeader = self::bodyRefreshToken($this->signedIn()->tokens);
        $fromBody   = self::bodyRefreshToken($this->signedIn()->tokens);

        $header = self::sessionsOf($this->guardServing(['HTTP_X_REFRESH_TOKEN' => $fromHeader]))->refresh(self::servedToken(), self::requestClient());
        $body   = self::sessionsOf($this->guardServing([], ['refresh_token' => $fromBody]))->refresh(self::servedToken(), self::requestClient());
        $refuse = self::sessionsOf($this->guardServing([], ['refresh_token' => 'not-a-token']))->refresh(self::servedToken(), self::requestClient());

        self::assertSame([true, RefreshTokenSource::HEADER], [$header?->isRefreshed(), $header?->source]);
        self::assertSame([true, RefreshTokenSource::BODY], [$body?->isRefreshed(), $body?->source]);
        self::assertSame([FailureReason::TOKEN_INVALID, RefreshTokenSource::BODY], [$refuse?->reason, $refuse?->source]);
    }

    /**
     * A request that carries no refresh token is not a refresh: `null`, and
     * nothing is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithoutATokenIsNotARefresh(): void
    {
        $this->recordEvents(self::EVENTS);

        self::assertNull(self::sessionsOf($this->freshGuard())->refresh(self::servedToken(), self::requestClient()));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A token the transport refuses is a refused refresh with no source.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenTheTransportRefusesIsARefusedRefresh(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $token   = self::bodyRefreshToken($session->tokens);
        $before  = $this->refreshKeyOf($session);
        $guard   = $this->guardServing(['HTTP_X_REFRESH_TOKEN' => $token], ['refresh_token' => $token]);

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($guard)->refresh(self::servedToken(), self::requestClient());

        self::assertNotNull($result);
        self::assertSame([FailureReason::REFRESH_TOKEN_CONFLICT, null, null], [$result->reason, $result->retryAfter, $result->source]);
        self::assertSame(self::REFUSAL, $this->recordedClasses());
        $attempting = $this->recordedEvent(Attempting::class);

        self::assertSame(['api', [], false], [$attempting->guard, $attempting->credentials, $attempting->remember]);
        self::assertNull($this->recordedEvent(Failed::class)->user);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::REFRESH, FailureReason::REFRESH_TOKEN_CONFLICT], [$failure->flow, $failure->reason]);
        self::assertSame(['api', self::CLIENT_IP, null], [$failure->context->guard, $failure->context->client->ip, $failure->context->identityId]);
        self::assertSame($before, $this->refreshKeyOf($session));
        self::assertTrue($guard->guest());
    }

    /**
     * The rotation is reported before the guard is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRotationIsReportedBeforeTheBind(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $before  = $this->refreshKeyOf($session);
        $guard   = $this->freshGuard();

        $this->recordEvents(self::EVENTS);

        Event::listen(Login::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        try {
            self::sessionsOf($guard)->refresh(self::bodyToken($session->tokens), self::requestClient());
            self::fail('Expected the listener to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertSame([Attempting::class, Refreshed::class, SignedIn::class, Validated::class, Login::class], $this->recordedClasses());
        self::assertNotSame($before, $this->refreshKeyOf($session));
    }

    /**
     * The report and then the bind wait for the caller's commit, and a rollback
     * drops both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportAndTheBindWaitForTheCallersCommit(): void
    {
        $this->seedIdentity();

        $committed  = $this->signedIn();
        $rolledBack = $this->signedIn();
        $guard      = $this->freshGuard();
        $bound      = null;

        $this->recordEvents(self::EVENTS);

        DB::transaction(function () use ($guard, $committed, &$bound): void {
            self::assertTrue(self::sessionsOf($guard)->refresh(self::bodyToken($committed->tokens), self::requestClient())->isRefreshed());
            self::assertSame([Attempting::class], $this->recordedClasses());

            $bound = $guard->hasUser();
        });

        self::assertFalse($bound);
        self::assertSame(self::REFRESHED, $this->recordedClasses());
        self::assertSame($committed->record->getKey(), $guard->session()?->getSessionIdentifier());

        $guard = $this->freshGuard();

        $this->recordEvents(self::EVENTS);

        DB::beginTransaction();

        self::assertTrue(self::sessionsOf($guard)->refresh(self::bodyToken($rolledBack->tokens), self::requestClient())->isRefreshed());

        DB::rollBack();

        self::assertSame([Attempting::class], $this->recordedClasses());
        self::assertFalse($guard->hasUser());
    }

    /**
     * Rows of `[what the caller's transaction wrote to the refreshed session
     * before its commit]`.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChangesBeforeTheCommit(): iterable
    {
        yield 'revoked' => [['revoked_at' => '2026-04-06 12:00:00', 'revoked_reason' => 'signed_out']];
        yield 'returned to pending' => [['status' => 'pending']];
        yield 'another session put under its key' => [['generation' => '00000000-0000-7000-8000-000000000000']];
        yield 'switched to another principal' => [['principal_id' => '999999']];
        yield 'switched to another tenant' => [['tenant_id' => 'another-tenant']];
    }

    /**
     * A deferred bind is skipped for a session the same transaction changed.
     *
     * @param  array<string, mixed>  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesBeforeTheCommit')]
    public function testADeferredBindIsNotMadeForASessionChangedBeforeTheCommit(array $change): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $guard   = $this->freshGuard();

        $this->recordEvents([Refreshed::class, Login::class]);

        DB::transaction(static function () use ($guard, $session, $change): void {
            self::assertTrue(self::sessionsOf($guard)->refresh(self::bodyToken($session->tokens), self::requestClient())->isRefreshed());

            DB::table('authentication_sessions')->update($change);
        });

        self::assertFalse($guard->hasUser());
        self::assertSame([Refreshed::class], $this->recordedClasses());
    }

    /**
     * A session service handed out before a dispatcher is swapped in reports
     * its refresh to the dispatcher bound then.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAServiceHandedOutBeforeAFakeReportsToIt(): void
    {
        $this->seedIdentity();

        $session  = $this->signedIn();
        $sessions = self::sessionsOf($this->freshGuard());

        Event::fake(self::EVENTS);

        self::assertTrue($sessions->refresh(self::bodyToken($session->tokens), self::requestClient())->isRefreshed());

        foreach (self::REFRESHED as $class) {
            Event::assertDispatched($class);
        }

        Event::assertNotDispatched(Failed::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
    }

    /**
     * A cookie application refreshes from plain values, and the result carries
     * the cookie instead of the token.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationRefreshesFromPlainValues(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn(self::BROWSER);
        $guard   = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($guard)->refresh(self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE), self::sameSiteClient());

        self::assertNotNull($result);
        self::assertTrue($result->isRefreshed());
        self::assertSame(RefreshTokenSource::COOKIE, $result->source);

        $tokens = $result->session?->tokens;

        self::assertNotNull($tokens);
        self::assertNull($tokens->refreshToken);
        self::assertNotNull($tokens->refreshCookie);
        self::assertSame(['__Secure-admin_refresh_token', '/auth'], [$tokens->refreshCookie->name, $tokens->refreshCookie->path]);
        self::assertEquals([$tokens->refreshCookie->cookie()], $tokens->refreshCookie->attachTo(new Response)->headers->getCookies());

        self::assertSame(self::REFRESHED, $this->recordedClasses());
        self::assertSame(self::sameSiteClient()->ip, $this->recordedEvent(Refreshed::class)->context->client->ip);
        self::assertSame(self::PLAIN_AGENT, $this->recordedEvent(SignedIn::class)->context->client->userAgent);
        self::assertSame(self::PLAIN_IP, $this->recordedEvent(SessionAuthenticated::class)->context->client->ip);
        self::assertSame($session->record->getKey(), $guard->session()?->getSessionIdentifier());
        $again = self::presentedToken((string) $tokens->refreshCookie->cookie()->getValue(), RefreshTokenSource::COOKIE);

        self::assertTrue($this->sessions(self::BROWSER)->refresh($again, self::sameSiteClient())->isRefreshed());
    }

    /**
     * The bind after a plain refresh records the client given as the last use.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBindAfterAPlainRefreshRecordsTheClientGivenAsTheLastUse(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn(self::BROWSER);
        $client  = self::sameSiteClient();
        $key     = $session->record->getKey();

        $this->moveTo(CarbonImmutable::now()->addSeconds(30));

        $presented = self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE);
        $within    = self::sessionsOf($this->crossSiteGuard(self::BROWSER))->refresh($presented, $client);

        self::assertTrue($within->isRefreshed());
        self::assertNotNull($within->session);

        $record = Session::query()->whereKey($key)->sole();

        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$record->getRawOriginal('last_used_ip'), $record->getRawOriginal('last_used_user_agent')]);

        $this->moveTo(CarbonImmutable::now()->addSeconds(61));

        $guard = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents(self::EVENTS);

        $presented = self::presentedToken(self::cookieTokenOf($within->session), RefreshTokenSource::COOKIE);

        self::assertTrue(self::sessionsOf($guard)->refresh($presented, $client)->isRefreshed());

        $record = Session::query()->whereKey($key)->sole();

        self::assertSame($client, $this->recordedEvent(PrincipalAssigned::class)->context->client);
        self::assertSame($client, $this->recordedEvent(SessionAuthenticated::class)->context->client);
        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], [$record->getRawOriginal('last_used_ip'), $record->getRawOriginal('last_used_user_agent')]);
        self::assertSame(CarbonImmutable::now()->toDateTimeString(), $record->getRawOriginal('last_used_at'));

        $this->recordEvents(self::EVENTS);

        $guard->setSession($record);

        self::assertSame([self::CROSS_SITE_IP, 'CrossSite/1.0'], [
            $this->recordedEvent(SessionAuthenticated::class)->context->client->ip,
            $this->recordedEvent(SessionAuthenticated::class)->context->client->userAgent,
        ]);
    }

    /**
     * A deferred bind after a plain refresh still describes the client given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredBindAfterAPlainRefreshDescribesTheClientGiven(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 0);

        $this->seedIdentity();

        $session   = $this->signedIn(self::BROWSER);
        $presented = self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE);
        $client    = self::sameSiteClient();
        $guard     = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents(self::EVENTS);

        DB::transaction(function () use ($guard, $presented, $client): void {
            self::assertTrue(self::sessionsOf($guard)->refresh($presented, $client)->isRefreshed());
            self::assertSame([Attempting::class], $this->recordedClasses());
        });

        $record = Session::query()->whereKey($session->record->getKey())->sole();

        self::assertSame(self::REFRESHED, $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(SessionAuthenticated::class)->context->client);
        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], [$record->getRawOriginal('last_used_ip'), $record->getRawOriginal('last_used_user_agent')]);
    }

    /**
     * A cookie token with a client that fails the same-site check is refused as
     * `cross_site_request`.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCrossSiteClients')]
    public function testACookieTokenFromACrossSiteClientIsRefused(ClientContext $client): void
    {
        $this->seedIdentity();

        $session = $this->signedIn(self::BROWSER);
        $token   = self::cookieTokenOf($session);
        $before  = $this->refreshKeyOf($session);
        $guard   = $this->guardServing(['HTTP_ORIGIN' => 'http://localhost', 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'], [], [self::COOKIE => $token], self::BROWSER);

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($guard)->refresh(self::presentedToken($token, RefreshTokenSource::COOKIE), $client);

        self::assertNotNull($result);
        self::assertSame([FailureReason::CROSS_SITE_REQUEST, null, RefreshTokenSource::COOKIE], [$result->reason, $result->retryAfter, $result->source]);
        self::assertSame(self::REFUSAL, $this->recordedClasses());

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::REFRESH, FailureReason::CROSS_SITE_REQUEST], [$failure->flow, $failure->reason]);
        self::assertSame($client, $failure->context->client);
        self::assertSame($before, $this->refreshKeyOf($session));
        self::assertTrue($guard->guest());
    }

    /**
     * Rows of `[the guard, the source, the carriers besides the source, the
     * reason]` the transport's judgement of a presented token refuses.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource, 2: list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>, 3: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideJudgedRefusals(): iterable
    {
        yield 'the body, to a cookie application' => [self::BROWSER, RefreshTokenSource::BODY, [], FailureReason::REFRESH_TRANSPORT_MISMATCH];
        yield 'a header, to a cookie application' => [self::BROWSER, RefreshTokenSource::HEADER, [], FailureReason::REFRESH_TRANSPORT_MISMATCH];
        yield 'the cookie, to a body application' => ['api', RefreshTokenSource::COOKIE, [], FailureReason::REFRESH_TRANSPORT_MISMATCH];
        yield 'the cookie twice' => [self::BROWSER, RefreshTokenSource::COOKIE, [RefreshTokenSource::COOKIE], FailureReason::REFRESH_TOKEN_CONFLICT];
        yield 'the body and a header' => ['api', RefreshTokenSource::BODY, [RefreshTokenSource::HEADER], FailureReason::REFRESH_TOKEN_CONFLICT];
    }

    /**
     * A live token with facts the transport refuses is refused with its reason
     * before the exchange.
     *
     * @param  string  $guardName
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>  $others
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideJudgedRefusals')]
    public function testATokenTheJudgementRefusesIsARefusedRefresh(string $guardName, RefreshTokenSource $source, array $others, FailureReason $reason): void
    {
        $this->seedIdentity();

        $session = $this->signedIn($guardName);
        $token   = $guardName === self::BROWSER ? self::cookieTokenOf($session) : $session->tokens->refreshToken?->reveal();
        $before  = $this->refreshKeyOf($session);
        $guard   = $this->crossSiteGuard($guardName);

        self::assertIsString($token);

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($guard)->refresh(self::presentedToken($token, $source, [$source, ...$others]), self::sameSiteClient());

        self::assertNotNull($result);
        self::assertSame([$reason, $source], [$result->reason, $result->source]);
        self::assertSame(self::REFUSAL, $this->recordedClasses());
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame($before, $this->refreshKeyOf($session));
    }

    /**
     * A body application refreshes from plain values without same-site facts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABodyApplicationRefreshesFromPlainValuesWithoutSameSiteFacts(): void
    {
        $this->seedIdentity();

        foreach ([RefreshTokenSource::BODY, RefreshTokenSource::HEADER] as $source) {

            $token  = $this->signedIn()->tokens->refreshToken?->reveal();
            $result = self::sessionsOf($this->crossSiteGuard())->refresh(self::presentedToken((string) $token, $source), self::crossSiteClient());
            $tokens = $result->session?->tokens;

            self::assertTrue($result->isRefreshed(), $source->value);
            self::assertSame($source, $result->source);
            self::assertNotNull($tokens?->refreshToken);
            self::assertNull($tokens->refreshCookie);
        }
    }

    /**
     * Rows of `[the reason]` the transport's extraction refuses a request's
     * refresh token with.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideTransportReasons(): iterable
    {
        foreach ([FailureReason::REFRESH_TOKEN_CONFLICT, FailureReason::REFRESH_TRANSPORT_MISMATCH, FailureReason::TOKEN_INVALID] as $reason) {
            yield $reason->value => [$reason];
        }
    }

    /**
     * A reason the transport answered, handed in, is a reported refusal with no
     * source.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTransportReasons')]
    public function testAReasonTheTransportAnsweredIsAReportedRefusal(FailureReason $reason): void
    {
        $guard  = $this->crossSiteGuard(self::BROWSER);
        $client = self::sameSiteClient();

        $this->recordEvents(self::EVENTS);

        $result = self::sessionsOf($guard)->refresh($reason, $client);

        self::assertNotNull($result);
        self::assertSame([$reason, null, null], [$result->reason, $result->retryAfter, $result->source]);
        self::assertSame(self::REFUSAL, $this->recordedClasses());

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::REFRESH, $reason, null], [$failure->flow, $failure->reason, $failure->context->identityId]);
        self::assertSame($client, $failure->context->client);
        self::assertTrue($guard->guest());
    }

    /**
     * A reason the transport never answers, handed in, throws before anything
     * is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReasonTheTransportNeverAnswersIsRefusedAsTheCallersError(): void
    {
        $this->recordEvents(self::EVENTS);

        foreach ([self::BROWSER, 'api'] as $guard) {
            foreach ([FailureReason::RATE_LIMITED, FailureReason::SESSION_REVOKED, FailureReason::ROTATION_REUSE, FailureReason::CROSS_SITE_REQUEST] as $reason) {
                try {
                    self::sessionsOf($this->crossSiteGuard($guard))->refresh($reason, self::sameSiteClient());

                    self::fail("A refresh took {$reason->value} as what the transport read.");
                } catch (\InvalidArgumentException $exception) {
                    $message = "The transport never refuses a refresh token as `{$reason->value}`: hand in only what `extract()` answered.";

                    self::assertSame($message, $exception->getMessage());
                }
            }
        }

        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Nothing presented is not a refresh, on either application: `null`, and
     * nothing is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingPresentedIsNotARefresh(): void
    {
        $this->recordEvents(self::EVENTS);

        self::assertNull(self::sessionsOf($this->crossSiteGuard(self::BROWSER))->refresh(null, self::sameSiteClient()));
        self::assertNull(self::sessionsOf($this->crossSiteGuard())->refresh(null, self::crossSiteClient()));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Grace and replay hold for a plain refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGraceAndReplayHoldForAPlainRefresh(): void
    {
        $this->seedIdentity();

        $session  = $this->signedIn(self::BROWSER);
        $replayed = self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE);
        $current  = self::sessionsOf($this->crossSiteGuard(self::BROWSER))->refresh($replayed, self::sameSiteClient())->session?->tokens->refreshCookie;
        $retried  = self::sessionsOf($this->crossSiteGuard(self::BROWSER))->refresh($replayed, self::sameSiteClient())->session?->tokens->refreshCookie;

        self::assertNotNull($current);
        self::assertNotNull($retried);

        $rotation = $this->rotationOf($current->cookie()->getValue());

        self::assertIsString($rotation);
        self::assertNotSame('', $rotation);
        self::assertSame($rotation, $this->rotationOf($retried->cookie()->getValue()));

        $this->moveTo(CarbonImmutable::now()->addMinute());
        $this->recordEvents([SessionRevoked::class]);

        $client = self::sameSiteClient();
        $result = self::sessionsOf($this->crossSiteGuard(self::BROWSER))->refresh($replayed, $client);

        self::assertSame(FailureReason::ROTATION_REUSE, $result->reason);
        self::assertSame('rotation_reuse', Session::query()->whereKey($session->record->getKey())->value('revoked_reason'));
        self::assertSame($client, $this->recordedEvent(SessionRevoked::class)->context->client);
    }

    /**
     * A plain refresh's attempt limit counts the client given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainRefreshIsLimitedByTheClientGiven(): void
    {
        config()->set('authentication.rate_limits.refresh.per_ip.max', 1);

        $invalid = self::presentedToken('not-a-token', RefreshTokenSource::BODY);
        $refresh = fn (ClientContext $client): RefreshResult => self::sessionsOf($this->freshGuard())->refresh($invalid, $client);

        self::assertSame(FailureReason::TOKEN_INVALID, $refresh(self::crossSiteClient())->reason);

        $limited = $refresh(self::crossSiteClient());

        self::assertSame([FailureReason::RATE_LIMITED, 60], [$limited->reason, $limited->retryAfter]);
        self::assertSame(FailureReason::TOKEN_INVALID, $refresh(new ClientContext('192.0.2.45', self::PLAIN_AGENT))->reason);

        $guardsAddress = new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT);

        self::assertSame(FailureReason::TOKEN_INVALID, $refresh($guardsAddress)->reason);
        self::assertSame(FailureReason::RATE_LIMITED, $refresh($guardsAddress)->reason);
        self::assertSame(FailureReason::TOKEN_INVALID, $refresh(new ClientContext(null, self::PLAIN_AGENT))->reason);
    }

    /**
     * A plain refresh from a client without an address is limited by the
     * token's session alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainRefreshFromAClientWithoutAnAddressIsLimitedByTheTokensSession(): void
    {
        config()->set('authentication.rate_limits.refresh.per_identifier.max', 1);

        $this->seedIdentity();

        $client   = new ClientContext(null, self::PLAIN_AGENT);
        $other    = self::presentedToken((string) $this->signedIn()->tokens->refreshToken?->reveal(), RefreshTokenSource::BODY);
        $replayed = self::presentedToken((string) $this->signedIn()->tokens->refreshToken?->reveal(), RefreshTokenSource::BODY);
        $current  = self::sessionsOf($this->crossSiteGuard())->refresh($replayed, $client)->session?->tokens->refreshToken?->reveal();

        $this->moveTo(CarbonImmutable::now()->addMinute());

        self::assertSame(FailureReason::ROTATION_REUSE, self::sessionsOf($this->crossSiteGuard())->refresh($replayed, $client)->reason);

        $limited = self::sessionsOf($this->crossSiteGuard())->refresh(self::presentedToken((string) $current, RefreshTokenSource::BODY), $client);

        self::assertSame([FailureReason::RATE_LIMITED, 60], [$limited->reason, $limited->retryAfter]);
        self::assertTrue(self::sessionsOf($this->crossSiteGuard())->refresh($other, $client)->isRefreshed());
    }

    /**
     * A plain refresh's report and bind wait for the caller's commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainRefreshWaitsForTheCallersCommit(): void
    {
        $this->seedIdentity();

        $committed  = $this->signedIn(self::BROWSER);
        $rolledBack = $this->signedIn(self::BROWSER);
        $before     = $this->refreshKeyOf($rolledBack);
        $guard      = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents(self::EVENTS);

        DB::transaction(function () use ($guard, $committed): void {
            $presented = self::presentedToken(self::cookieTokenOf($committed), RefreshTokenSource::COOKIE);

            self::assertTrue(self::sessionsOf($guard)->refresh($presented, self::sameSiteClient())->isRefreshed());
            self::assertSame([Attempting::class], $this->recordedClasses());
        });

        self::assertSame(self::REFRESHED, $this->recordedClasses());
        self::assertSame(self::PLAIN_IP, $this->recordedEvent(Refreshed::class)->context->client->ip);
        self::assertSame($committed->record->getKey(), $guard->session()?->getSessionIdentifier());

        $guard = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents(self::EVENTS);

        DB::beginTransaction();

        $presented = self::presentedToken(self::cookieTokenOf($rolledBack), RefreshTokenSource::COOKIE);

        self::assertTrue(self::sessionsOf($guard)->refresh($presented, self::sameSiteClient())->isRefreshed());

        DB::rollBack();

        self::assertSame([Attempting::class], $this->recordedClasses());
        self::assertFalse($guard->hasUser());
        self::assertSame($before, $this->refreshKeyOf($rolledBack));
    }

    /**
     * A refresh expecting its own session, or none, is made; another expected
     * id refuses it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshExpectingItsOwnSessionIsMade(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $id      = IdentifierCoercion::stringify($session->record->getSessionIdentifier());
        $token   = (string) $session->tokens->refreshToken?->reveal();
        $before  = $this->refreshKeyOf($session);

        self::assertSame(FailureReason::SESSION_MISMATCH, $this->sessions()->refresh(PresentedRefreshToken::fromBody($token), self::requestClient(), 42)->reason);
        self::assertSame($before, $this->refreshKeyOf($session));

        $refreshed = $this->sessions()->refresh(PresentedRefreshToken::fromBody($token), self::requestClient(), $id);

        self::assertTrue($refreshed->isRefreshed());
        self::assertNotSame($before, $this->refreshKeyOf($session));

        $next = (string) $refreshed->session?->tokens->refreshToken?->reveal();

        self::assertTrue($this->sessions()->refresh(PresentedRefreshToken::fromBody($next), self::requestClient(), null)->isRefreshed());
    }

    /**
     * A token proving another session than expected is refused as
     * `session_mismatch`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshProvingAnotherSessionThanExpectedIsRefused(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $other   = $this->signedIn();
        $id      = IdentifierCoercion::stringify($session->record->getSessionIdentifier());
        $before  = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->where('id', $id)->sole());
        $limiter = \Mockery::mock(AttemptLimiter::class);

        $limiter->shouldReceive('blocked')->once()->andReturnNull();
        $limiter->shouldReceive('recordFailure')->once()->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->flow === AttemptFlow::REFRESH
            && $subject->guard                                                                                                          === 'api'
            && $subject->identifier                                                                                                     === $id
            && $subject->ip                                                                                                             === self::CLIENT_IP));

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([...self::EVENTS, SessionRevoked::class]);

        $result = $this->sessions()->refresh(
            self::bodyToken($session->tokens),
            self::requestClient(),
            self::modelKey($other->record),
        );

        self::assertSame([false, FailureReason::SESSION_MISMATCH], [$result->isRefreshed(), $result->reason]);
        self::assertSame(self::REFUSAL, $this->recordedClasses());

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::REFRESH, FailureReason::SESSION_MISMATCH], [$failed->flow, $failed->reason]);
        EventContextAssertions::assertSession($session->record, $failed->context);
        self::assertEquals($before, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->where('id', $id)->sole()));
        self::assertTrue(Auth::guard('api')->guest());
    }

    /**
     * The token is judged before the expected session is compared.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTokenIsJudgedBeforeTheExpectedSessionIsCompared(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $other   = $this->signedIn();
        $revoked = $this->signedIn();
        $id      = self::modelKey($session->record);
        $old     = self::bodyToken($session->tokens);

        self::assertTrue($this->sessions()->refresh($old, self::requestClient())->isRefreshed());

        $current = $this->refreshKeyOf($session);

        self::assertSame(FailureReason::SESSION_MISMATCH, $this->sessions()->refresh($old, self::requestClient(), self::modelKey($other->record))->reason);
        self::assertSame($current, $this->refreshKeyOf($session));
        self::assertTrue($this->sessions()->refresh($old, self::requestClient(), $id)->isRefreshed());

        Session::query()->whereKey($revoked->record->getKey())->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);

        self::assertSame(
            FailureReason::SESSION_REVOKED,
            $this->sessions()->refresh(self::bodyToken($revoked->tokens), self::requestClient(), $id)->reason,
        );

        $this->moveTo(CarbonImmutable::now()->addMinutes(2));
        $this->recordEvents([SessionRevoked::class]);

        $replayed = $this->sessions()->refresh($old, self::requestClient(), self::modelKey($other->record));

        self::assertSame(FailureReason::ROTATION_REUSE, $replayed->reason);
        self::assertSame('rotation_reuse', Session::query()->whereKey($id)->value('revoked_reason'));
        self::assertNull(Session::query()->whereKey($other->record->getKey())->value('revoked_at'));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
    }

    /**
     * Configure the guards and providers.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.guards.' . self::BROWSER . '.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);
    }

    /**
     * Sign the identity with the email in on the guard.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The rotation id a cookie application's refresh token carries.
     *
     * @param  ?string  $token
     * @return mixed
     *
     * @throws \Throwable
     */
    private function rotationOf(#[\SensitiveParameter] ?string $token): mixed
    {
        return Auth::jwt(self::BROWSER)->parse((string) $token, TokenType::REFRESH)[Claims::JWT_ID->value] ?? null;
    }

    /**
     * Start a request from the test client with the server values, body and
     * cookies, and resolve the guard, `api` unless named, afresh for it.
     *
     * @param  array<string, string>  $server
     * @param  array<string, string>  $body
     * @param  array<string, string>  $cookies
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardServing(array $server, array $body = [], array $cookies = [], string $guard = 'api'): JwtGuard
    {
        $server = ['REMOTE_ADDR' => self::CLIENT_IP, 'HTTP_USER_AGENT' => self::CLIENT_AGENT, ...$server];

        app()->instance('request', Request::create('/refresh', 'POST', $body, $cookies, server: $server));

        Auth::forgetGuards();

        $resolved = app('auth')->guard($guard);

        self::assertInstanceOf(JwtGuard::class, $resolved);

        return $resolved;
    }

    /**
     * The refresh key the session stores now.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return mixed
     */
    private function refreshKeyOf(SignedInSession $session): mixed
    {
        return Session::query()->whereKey($session->record->getKey())->value('refresh_key');
    }

    /**
     * The claims of a token of the `api` guard.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function claimsOf(#[\SensitiveParameter] string $token, TokenType $type = TokenType::REFRESH): array
    {
        $claims = Auth::jwt('api')->parse($token, $type);

        self::assertNotNull($claims);

        return $claims;
    }

    /**
     * Move the clock, and the token library's, to the moment.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private function moveTo(CarbonImmutable $now): void
    {
        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();
    }
}
