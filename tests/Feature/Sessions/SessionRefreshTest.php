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
use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RefreshesSessions;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\TestCase;

/**
 * Feature tests of refreshing a session through the session service: the
 * rotated session it returns and the guard bound to it, the events in their
 * order, each refusal returned with its reason, `rate_limited` with its wait
 * rather than a thrown 429, and where a refresh read from the request found its
 * token; and a refresh from plain values, on a cookie application and a body
 * one, which judges the token and the client it is handed and reads nothing
 * from the guard's request.
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
    use InteractsWithSessions;

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
     * A refresh rotates the session's refresh token, reports the rotation with
     * `Refreshed` and then `SignedIn` (a refresh, on no new session), and then
     * binds the guard as a sign-in; the result carries the same session with
     * the new pair, the body the token was presented from, and no reason or
     * wait.
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

        $result = self::sessionsOf($guard)->refresh(PresentedRefreshToken::fromBody($session->tokens->refreshToken?->reveal()), self::requestClient());

        self::assertTrue($result->isRefreshed());
        self::assertFalse($result->isFailed());
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertSame(RefreshTokenSource::BODY, $result->source);

        $refreshed = $result->session;

        self::assertInstanceOf(SignedInSession::class, $refreshed);
        self::assertTrue($identity->is($refreshed->identity));
        self::assertSame($session->record->getKey(), $refreshed->record->getKey());
        self::assertSame('password', $refreshed->method);
        self::assertNotSame($before, $this->refreshKeyOf($session));

        $rotation = $this->claimsOf($refreshed->tokens->refreshToken?->reveal())[Claims::JWT_ID->value] ?? null;

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
     * The bind events carry the tenant the refresh admitted the principal in
     * and the sign-in method the session records, as the rotation's report
     * does.
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

        self::assertTrue(self::sessionsOf($guard)->refresh(PresentedRefreshToken::fromBody($session->tokens->refreshToken?->reveal()), self::requestClient())->isRefreshed());

        foreach ($this->recorded as $event) {

            self::assertInstanceOf(AuthenticationEvent::class, $event);

            $context = $event->context();

            EventContextAssertions::assertTenant($tenant, $context);
            EventContextAssertions::assertPrincipal($membership, $context);
            self::assertSame('password', $context->method);
        }

        self::assertCount(3, $this->recorded);
        self::assertTrue($tenant->is($guard->tenant()));
    }

    /**
     * Every refusal of the exchange is returned with its reason, after
     * `Attempting`, Laravel's `Failed` (no user, no credentials) and
     * `AuthenticationFailed` with the same reason, and binds nothing.
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
            self::sessionsOf($this->freshGuard())->refresh(PresentedRefreshToken::fromBody($replayed->tokens->refreshToken?->reveal()), self::requestClient())->isRefreshed(),
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
     * A refresh the limits refuse is returned as `rate_limited` with the wait
     * the failure reports, after the same events as any refusal; nothing is
     * thrown.
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

        $fromHeader = $this->signedIn()->tokens->refreshToken?->reveal();
        $fromBody   = $this->signedIn()->tokens->refreshToken?->reveal();

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
     * A token the transport refuses is a refused refresh, reported with the
     * transport's reason and the request's client and no identity, returned
     * with no source, and the session is left as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenTheTransportRefusesIsARefusedRefresh(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $token   = $session->tokens->refreshToken?->reveal();
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
     * The rotation is reported before the guard is bound: a `Login` listener
     * that throws propagates, after `Refreshed` and `SignedIn` were dispatched
     * for the rotation already written.
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
            self::sessionsOf($guard)->refresh(PresentedRefreshToken::fromBody($session->tokens->refreshToken?->reveal()), self::requestClient());
            self::fail('Expected the listener to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertSame([Attempting::class, Refreshed::class, SignedIn::class, Validated::class, Login::class], $this->recordedClasses());
        self::assertNotSame($before, $this->refreshKeyOf($session));
    }

    /**
     * Inside the caller's transaction the rotation's report and then the bind
     * wait for the commit, in that order, as with no transaction open, and a
     * rollback drops both, leaving the guard unbound.
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
            self::assertTrue(self::sessionsOf($guard)->refresh(PresentedRefreshToken::fromBody($committed->tokens->refreshToken?->reveal()), self::requestClient())->isRefreshed());
            self::assertSame([Attempting::class], $this->recordedClasses());

            $bound = $guard->hasUser();
        });

        self::assertFalse($bound);
        self::assertSame(self::REFRESHED, $this->recordedClasses());
        self::assertSame($committed->record->getKey(), $guard->session()?->getSessionIdentifier());

        $guard = $this->freshGuard();

        $this->recordEvents(self::EVENTS);

        DB::beginTransaction();

        self::assertTrue(self::sessionsOf($guard)->refresh(PresentedRefreshToken::fromBody($rolledBack->tokens->refreshToken?->reveal()), self::requestClient())->isRefreshed());

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
     * A refresh's bind that waited for the commit reads the session again
     * first: one the same transaction revoked, returned to pending, replaced or
     * switched to another principal or tenant is never bound, though its
     * rotation is reported.
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
            self::assertTrue(self::sessionsOf($guard)->refresh(PresentedRefreshToken::fromBody($session->tokens->refreshToken?->reveal()), self::requestClient())->isRefreshed());

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

        self::assertTrue($sessions->refresh(PresentedRefreshToken::fromBody($session->tokens->refreshToken?->reveal()), self::requestClient())->isRefreshed());

        foreach (self::REFRESHED as $class) {
            Event::assertDispatched($class);
        }

        Event::assertNotDispatched(Failed::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
    }

    /**
     * A cookie application refreshes from plain values: the token presented
     * from its cookie and a same-site client, on a guard whose own request is
     * cross-site, from another address and carries no cookie. The result
     * carries the cookie that sets the new refresh token, never the token, and
     * refreshes again; the rotation and the guard's bind are reported with the
     * client given.
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
     * The guard's bind after a plain refresh describes the client given, not
     * the guard's own request: its `PrincipalAssigned` and
     * `SessionAuthenticated` carry it, so the last use the bind records is that
     * client's once the last-use throttle allows it (inside the window nothing
     * is written over the sign-in's). The guard keeps no client: a later bind
     * in the same request describes the request.
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
     * A plain refresh inside the caller's transaction binds once it commits,
     * and that deferred bind still describes the client given, so with a
     * last-use throttle that records every use the last use is that client's.
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
     * A cookie application refuses a token presented from its cookie with a
     * client the same-site check refuses, as `cross_site_request`, though the
     * guard's own request is same-site and carries the same cookie: the refusal
     * is reported with the client given, the result says where the token was
     * presented, and the session is left as it was.
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
     * A live token presented with facts the transport refuses is refused with
     * its reason before the exchange, from a same-site client too, reported
     * as the request form reports it, and its result says where it was
     * presented; the session is left as it was.
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
     * A body application refreshes from a token presented from its body field
     * or its header with a client that has no same-site facts at all: neither
     * carrier is sent by a browser by itself. The result says which, and
     * carries the new refresh token, no cookie.
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
     * A reason the extraction answered, handed in, is a refused refresh
     * reported as a refusal of the judgement is, with the client given, and
     * with no source: nothing was presented.
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
     * A reason the extraction never answers, handed in, is the caller's error:
     * it throws before anything is dispatched, on either application, the
     * same-site judgement's `cross_site_request` included, which only the
     * package makes, on the client.
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
     * A token presented again inside the grace window gets the session's
     * current credential through the plain form too, and once the window has
     * closed it is a replay: the session is revoked as `rotation_reuse`,
     * reported with the client given.
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
     * The attempt limit of a plain refresh counts the client given: a refusal
     * from its address limits the next from it, as `rate_limited` with the
     * wait, but not one from another address; and a client with no address is
     * not counted by the guard's own request's address, though that address's
     * count is full.
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
     * A plain refresh from a client with no IP address is limited by the
     * token's session alone: a replay of the session's token fills its count,
     * so the session's current token is then refused as `rate_limited` with the
     * wait, while another session's token still refreshes for the same client.
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
     * Inside the caller's transaction a plain refresh's report and bind wait
     * for the commit, the report carrying the client given, and a rollback
     * drops both.
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
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

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
