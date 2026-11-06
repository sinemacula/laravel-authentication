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
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignOutResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\StubBareSession;

/**
 * Feature tests of signing out by whichever credential the request carries, on
 * a body application: a request bound to its session by a live access token is
 * signed out as `signOut()` signs it out; otherwise its binding is forgotten
 * and the session its refresh token proves is revoked, so a client whose access
 * token expired, or that holds none, still signs out; a refused refresh token
 * signs the request out all the same and is reported with the flow `sign_out`
 * and its reason, and never as a failed authentication; and signing out from
 * plain values, on a cookie application and a body one, which judges the token
 * and the client it is handed, reads nothing from the guard's request, and
 * clears a cookie application's cookie only for a same-site client.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionSignOut::class)]
#[CoversClass(SignOutResult::class)]
#[CoversClass(SessionService::class)]
#[CoversTrait(EndsSessions::class)]
final class SessionSignOutTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<class-string> Every event a sign-out could dispatch. */
    private const array EVENTS = [Attempting::class, Failed::class, SessionRevoked::class, Logout::class, AuthenticationFailed::class];

    /** @var string The cookie application, over the same identities. */
    private const string BROWSER = 'browser';

    /** @var list<string> The cookie application's refresh cookie's name and path. */
    private const array COOKIE = ['__Secure-browser_refresh_token', '/auth'];

    /** @var list<class-string> The events of a sign-out, without what a bearer token reports. */
    private const array SIGN_OUT_EVENTS = [Attempting::class, Failed::class, SessionRevoked::class, Logout::class];

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
     * A request bound to its session by a live access token signs that session
     * out, as `signOut()` does, and leaves the refresh token it also carries
     * unread, even one of another session; a body application has no cookie to
     * clear.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundSessionIsSignedOutWithoutReadingTheRefreshToken(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $other    = $this->signedIn();
        $sessions = $this->serving(bearer: $session->tokens->accessToken->reveal(), body: ['refresh_token' => self::refreshOf($other)]);

        $this->recordEvents(self::EVENTS);

        $result = self::signOutServed($sessions);

        self::assertTrue($result->isSignedOut());
        self::assertFalse($result->isFailed());
        self::assertNull($result->reason);
        self::assertNull($result->source);
        self::assertNull($result->forgetCookie);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertSame(RevocationReason::SIGNED_OUT, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertTrue($identity->is($this->recordedEvent(Logout::class)->user));
        self::assertSame('signed_out', $this->revokedReasonOf($session));
        self::assertNull($this->revokedReasonOf($other));
        self::assertTrue(Auth::guard('api')->guest());
    }

    /**
     * An access-only token, which names no stored session, is forgotten with
     * Laravel's `Logout` when the request carries no refresh token, and the
     * guard stays signed out for the rest of the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccessOnlyTokenIsForgottenWhenNoRefreshTokenComes(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->serving(bearer: Auth::jwt('api')->issueAccessToken($identity, $identity, null, null)->reveal());

        $this->recordEvents(self::EVENTS);

        $result = self::signOutServed($sessions);

        self::assertFalse($result->isSignedOut());
        self::assertFalse($result->isFailed());
        self::assertNull($result->source);
        self::assertSame([Logout::class], $this->recordedClasses());
        self::assertTrue($identity->is($this->recordedEvent(Logout::class)->user));
        self::assertFalse(Auth::guard('api')->check());
    }

    /**
     * An access-only token with a refresh token, signed out as a controller
     * does, forgets the access-only binding with `Logout`, and the refresh
     * token then signs the session it proves out, with a `Logout` of its own:
     * the sign-out by refresh credential stands apart from the guard's binding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccessOnlyTokenWithARefreshTokenSignsItsSessionOutWithALogoutEach(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $sessions = $this->serving(
            bearer: Auth::jwt('api')->issueAccessToken($identity, $identity, null, null)->reveal(),
            body: ['refresh_token' => self::refreshOf($session)],
        );

        $this->recordEvents(self::EVENTS);

        $result = self::signOutServed($sessions);

        self::assertTrue($result->isSignedOut());
        self::assertSame(RefreshTokenSource::BODY, $result->source);
        self::assertSame([Logout::class, SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertSame('signed_out', $this->revokedReasonOf($session));
        self::assertFalse(Auth::guard('api')->check());
    }

    /**
     * A binding to a session the package does not store, an Eloquent model the
     * application bound itself, is forgotten as an access-only token's is, with
     * `Logout`; the refresh token the request carries then signs its own
     * session out, with a `Logout` of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindingToASessionThePackageDoesNotStoreIsForgottenAndTheRefreshTokenSignsOut(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $sessions = $this->serving(body: ['refresh_token' => self::refreshOf($session)]);
        $guard    = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->authenticateAs($identity, $identity, new StubBareSession(['id' => 'bare-session']));

        $this->recordEvents(self::EVENTS);

        $result = self::signOutServed($sessions);

        self::assertTrue($result->isSignedOut());
        self::assertSame(RefreshTokenSource::BODY, $result->source);
        self::assertSame([Logout::class, SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertSame('signed_out', $this->revokedReasonOf($session));
        self::assertFalse(Auth::guard('api')->check());
    }

    /**
     * Rows of `[the server values and body carrying the token, the source]`:
     * the body field and the header of a body application.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(string): array{0: array<string, string>, 1: array<string, string>}, 1: \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideCarriers(): iterable
    {
        yield 'the body field' => [static fn (string $token): array => [[], ['refresh_token' => $token]], RefreshTokenSource::BODY];
        yield 'the header' => [static fn (string $token): array => [['HTTP_X_REFRESH_TOKEN' => $token], []], RefreshTokenSource::HEADER];
    }

    /**
     * A client whose access token has expired signs out by its refresh token:
     * the session is revoked as `signed_out` and reported by `SessionRevoked`,
     * `Logout` fires for its owner, reloaded through the guard's provider, and
     * the token no longer refreshes.
     *
     * @param  \Closure(string): array{0: array<string, string>, 1: array<string, string>}  $carrier
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCarriers')]
    public function testAClientWhoseAccessTokenExpiredSignsOutByItsRefreshToken(\Closure $carrier, RefreshTokenSource $source): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();

        $this->moveTo(CarbonImmutable::now()->addMinutes(20));

        [$server, $body] = $carrier(self::refreshOf($session));

        $sessions = $this->serving([...$server, 'HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()], $body);

        $this->recordEvents(self::SIGN_OUT_EVENTS);

        $result = self::signOutServed($sessions);

        self::assertTrue($result->isSignedOut());
        self::assertSame($source, $result->source);
        self::assertNull($result->reason);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::SIGNED_OUT, $revoked->reason);
        self::assertSame(['api', 'password'], [$revoked->context->guard, $revoked->context->method]);
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), $revoked->context->sessionId);
        EventContextAssertions::assertIdentity($identity, $revoked->context);
        self::assertTrue($identity->is($this->recordedEvent(Logout::class)->user));
        self::assertSame('api', $this->recordedEvent(Logout::class)->guard);
        self::assertSame('signed_out', $this->revokedReasonOf($session));
        self::assertSame(FailureReason::SESSION_REVOKED, $this->sessions()->refresh(PresentedRefreshToken::fromBody(self::refreshOf($session)), self::requestClient())->reason);
    }

    /**
     * A request that carries no credential at all signs nothing out and
     * dispatches nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithoutACredentialSignsNothingOut(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();

        $this->recordEvents(self::EVENTS);

        $result = self::signOutServed($this->serving());

        self::assertFalse($result->isSignedOut());
        self::assertFalse($result->isFailed());
        self::assertSame([], $this->recordedClasses());
        self::assertNull($this->revokedReasonOf($session));
    }

    /**
     * Every refresh token that proves no session signs the request out all the
     * same: the result says why, and where the token was read from;
     * `AuthenticationFailed` reports it with the flow `sign_out`, and neither
     * `Attempting` nor `Failed` fires. A replayed token revokes its session as
     * `rotation_reuse`, a pending session's token is `session_pending`, another
     * application's token is `token_invalid`, and one issued before a switch no
     * longer names the principal the session acts as.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryRefusedRefreshTokenIsReportedAsASignOutFailure(): void
    {
        $this->seedIdentity();

        $replayed = $this->signedIn();
        $pending  = $this->signedIn();
        $revoked  = $this->signedIn();
        $admin    = $this->signedIn('admin');

        self::assertTrue($this->sessions()->refresh(PresentedRefreshToken::fromBody(self::refreshOf($replayed)), self::requestClient())->isRefreshed());

        Session::query()->whereKey($pending->record->getKey())->update(['status' => 'pending']);
        Session::query()->whereKey($revoked->record->getKey())->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);

        $this->moveTo(CarbonImmutable::now()->addMinutes(2));

        $switched = $this->switchedMember();
        $cases    = [
            'not a token'               => ['api', 'not-a-token', FailureReason::TOKEN_INVALID],
            'a replayed token'          => ['api', self::refreshOf($replayed), FailureReason::ROTATION_REUSE],
            'a pending session'         => ['api', self::refreshOf($pending), FailureReason::SESSION_PENDING],
            'a revoked session'         => ['api', self::refreshOf($revoked), FailureReason::SESSION_REVOKED],
            'another application'       => ['api', self::refreshOf($admin), FailureReason::TOKEN_INVALID],
            'a token before the switch' => ['members', $switched, FailureReason::SESSION_PRINCIPAL_MISMATCH],
        ];

        foreach ($cases as $case => [$guard, $token, $reason]) {

            $sessions = $this->serving(body: ['refresh_token' => $token], guard: $guard);

            $this->recordEvents(self::EVENTS);

            $result = self::signOutServed($sessions);

            self::assertTrue($result->isFailed(), $case);
            self::assertFalse($result->isSignedOut(), $case);
            self::assertSame($reason, $result->reason, $case);
            self::assertSame(RefreshTokenSource::BODY, $result->source, $case);

            $classes = $reason === FailureReason::ROTATION_REUSE ? [SessionRevoked::class, AuthenticationFailed::class] : [AuthenticationFailed::class];

            self::assertSame($classes, $this->recordedClasses(), $case);

            $failure = $this->recordedEvent(AuthenticationFailed::class);

            self::assertSame([AuthenticationFlow::SIGN_OUT, $reason, $guard], [$failure->flow, $failure->reason, $failure->context->guard], $case);
            self::assertSame(self::CLIENT_IP, $failure->context->client->ip, $case);
        }

        self::assertSame('rotation_reuse', $this->revokedReasonOf($replayed));
        self::assertNull($this->revokedReasonOf($pending));
        self::assertNull($this->revokedReasonOf($admin));
    }

    /**
     * A refresh token the transport refuses is reported with the transport's
     * reason and no source: two different tokens in the body and the header
     * conflict, and a cookie sent to a body application is the wrong transport.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenTheTransportRefusesIsReportedWithItsReason(): void
    {
        $this->seedIdentity();

        $session    = $this->signedIn();
        $other      = $this->signedIn();
        $token      = self::refreshOf($session);
        $otherToken = self::refreshOf($other);
        $cases      = [
            'refresh_token_conflict'     => [['HTTP_X_REFRESH_TOKEN' => $otherToken], ['refresh_token' => $token], [], FailureReason::REFRESH_TOKEN_CONFLICT],
            'refresh_transport_mismatch' => [[], [], ['__Secure-api_refresh_token' => $token], FailureReason::REFRESH_TRANSPORT_MISMATCH],
        ];

        foreach ($cases as $case => [$server, $body, $cookies, $reason]) {

            $sessions = $this->serving($server, $body, $cookies);

            $this->recordEvents(self::EVENTS);

            $result = self::signOutServed($sessions);

            self::assertSame($reason, $result->reason, $case);
            self::assertNull($result->source, $case);
            self::assertFalse($result->isSignedOut(), $case);
            self::assertSame([AuthenticationFailed::class], $this->recordedClasses(), $case);
            $failure = $this->recordedEvent(AuthenticationFailed::class);

            self::assertSame([AuthenticationFlow::SIGN_OUT, $reason], [$failure->flow, $failure->reason], $case);
        }

        self::assertNull($this->revokedReasonOf($session));
        self::assertNull($this->revokedReasonOf($other));
    }

    /**
     * A session whose owner the guard's provider no longer returns is still
     * revoked by its refresh token, and reported naming the owner its row
     * records; no `Logout` fires, since no identity was signed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWhoseOwnerIsGoneIsRevokedWithoutLogout(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();

        DB::table('integration_identities')->where('id', $identity->getKey())->delete();

        $sessions = $this->serving(body: ['refresh_token' => self::refreshOf($session)]);

        $this->recordEvents(self::EVENTS);

        self::assertTrue(self::signOutServed($sessions)->isSignedOut());
        self::assertSame([SessionRevoked::class], $this->recordedClasses());

        $context = $this->recordedEvent(SessionRevoked::class)->context;

        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $context->identityId);
    }

    /**
     * A guard bound to a session that is already revoked has nothing left to
     * revoke: the sign-out forgets the binding and reports nothing revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundSessionAlreadyRevokedSignsNothingOut(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();

        Session::query()->whereKey($session->record->getKey())->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);

        $guard = $this->freshGuard();

        $guard->setSession(Session::query()->findOrFail($session->record->getKey()));

        $this->recordEvents(self::EVENTS);

        $result = self::signOutServed(self::sessionsOf($guard));

        self::assertFalse($result->isSignedOut());
        self::assertFalse($result->isFailed());
        self::assertSame([], $this->recordedClasses());
        self::assertNull($guard->session());
        self::assertSame('revoked', $this->revokedReasonOf($session));
    }

    /**
     * A body application's refresh token read by the application's own code
     * signs its session out: the guard, when it is bound to that session, is
     * forgotten, and `Logout` fires once for the owner; bound to another
     * session, it stays bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenHandedInSignsItsSessionOutAndForgetsABindingToIt(): void
    {
        $identity = $this->seedIdentity();
        $current  = $this->signedIn();
        $other    = $this->signedIn();
        $sessions = $this->serving(bearer: $current->tokens->accessToken->reveal());

        self::assertNotNull(Auth::guard('api')->user());

        $this->recordEvents(self::EVENTS);

        $elsewhere = $sessions->signOutWith(PresentedRefreshToken::fromBody(self::refreshOf($other)), self::requestClient());

        self::assertTrue($elsewhere->isSignedOut());
        self::assertSame(RefreshTokenSource::BODY, $elsewhere->source);
        self::assertNull($elsewhere->forgetCookie);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertTrue(Auth::guard('api')->check());

        $this->recordEvents(self::EVENTS);

        self::assertTrue($sessions->signOutWith(PresentedRefreshToken::fromBody(self::refreshOf($current)), self::requestClient())->isSignedOut());
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertTrue($identity->is($this->recordedEvent(Logout::class)->user));
        self::assertTrue(Auth::guard('api')->guest());
        self::assertSame('signed_out', $this->revokedReasonOf($current));
        self::assertSame('signed_out', $this->revokedReasonOf($other));
    }

    /**
     * The refresh token a sign-in returned signs its session out when it is
     * handed in as the `Secret` it was returned as.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenHandedInAsTheSecretItWasReturnedAsSignsItsSessionOut(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $token   = $session->tokens->refreshToken;

        self::assertNotNull($token);
        self::assertTrue($this->serving()->signOutWith(PresentedRefreshToken::fromBody($token), self::requestClient())->isSignedOut());
        self::assertSame('signed_out', $this->revokedReasonOf($session));
    }

    /**
     * A token handed in that proves no session is refused with its reason and
     * the body it was presented from, reported with the flow `sign_out`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenHandedInThatProvesNoSessionIsRefused(): void
    {
        $this->recordEvents(self::EVENTS);

        $result = $this->serving()->signOutWith(PresentedRefreshToken::fromBody('not-a-token'), self::requestClient());

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::TOKEN_INVALID, $result->reason);
        self::assertSame(RefreshTokenSource::BODY, $result->source);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::SIGN_OUT, $this->recordedEvent(AuthenticationFailed::class)->flow);
    }

    /**
     * No attempt limit applies to a sign-out: refused refresh tokens past the
     * refresh limits are each still judged, and a good one still signs out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoAttemptLimitAppliesToASignOut(): void
    {
        config()->set('authentication.rate_limits.refresh.per_ip.max', 1);

        $this->seedIdentity();

        $session = $this->signedIn();

        foreach (range(1, 3) as $attempt) {
            self::assertSame(
                FailureReason::TOKEN_INVALID,
                $this->serving()->signOutWith(PresentedRefreshToken::fromBody('not-a-token-' . $attempt), self::requestClient())->reason,
            );
        }

        self::assertTrue($this->serving()->signOutWith(PresentedRefreshToken::fromBody(self::refreshOf($session)), self::requestClient())->isSignedOut());
    }

    /**
     * A cookie application signs out from plain values: the token presented
     * from its cookie and a same-site client, on a guard whose own request is
     * cross-site, carries no cookie and is bound to another session by its
     * access token. The session the token proves is revoked, reported with the
     * client given, `Logout` fires for its owner, the guard stays bound to the
     * other session until its own token signs it out, and each result carries
     * the expired cookie.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationSignsOutFromPlainValues(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->signedIn(self::BROWSER);
        $current  = $this->signedIn(self::BROWSER);
        $sessions = $this->serving(['REMOTE_ADDR' => self::CROSS_SITE_IP], bearer: $current->tokens->accessToken->reveal(), guard: self::BROWSER);
        $client   = self::sameSiteClient();

        self::assertTrue(Auth::guard(self::BROWSER)->check());

        $this->recordEvents(self::EVENTS);

        $elsewhere = $sessions->signOutWith(self::presentedToken(self::cookieTokenOf($other), RefreshTokenSource::COOKIE), $client);

        self::assertTrue($elsewhere->isSignedOut());
        self::assertSame(RefreshTokenSource::COOKIE, $elsewhere->source);
        self::assertClears($elsewhere);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(SessionRevoked::class)->context->client);
        self::assertSame(RevocationReason::SIGNED_OUT, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertTrue($identity->is($this->recordedEvent(Logout::class)->user));
        self::assertTrue(Auth::guard(self::BROWSER)->check());

        $this->recordEvents(self::EVENTS);

        $signed = $sessions->signOutWith(self::presentedToken(self::cookieTokenOf($current), RefreshTokenSource::COOKIE), $client);

        self::assertTrue($signed->isSignedOut());
        self::assertClears($signed);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertTrue(Auth::guard(self::BROWSER)->guest());
        self::assertSame('signed_out', $this->revokedReasonOf($other));
        self::assertSame('signed_out', $this->revokedReasonOf($current));
    }

    /**
     * A sign-out from plain values binds nothing, so no event it dispatches
     * describes the guard's own request: on a guard serving a request from
     * another address, the package events of a refused and of a successful
     * plain sign-out carry the client given, and no bind event is dispatched
     * (Laravel's `Logout` carries no client).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainSignOutDispatchesNoEventDescribingTheGuardsRequest(): void
    {
        $this->seedIdentity();

        $session  = $this->signedIn();
        $sessions = $this->serving(['REMOTE_ADDR' => self::CROSS_SITE_IP]);
        $client   = self::sameSiteClient();
        $events   = [...self::EVENTS, Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class];

        $this->recordEvents($events);

        self::assertTrue($sessions->signOutWith(self::presentedToken('not-a-token', RefreshTokenSource::BODY), $client)->isFailed());
        self::assertTrue($sessions->signOutWith(self::presentedToken((string) $session->tokens->refreshToken?->reveal(), RefreshTokenSource::BODY), $client)->isSignedOut());
        self::assertSame([AuthenticationFailed::class, SessionRevoked::class, Logout::class], $this->recordedClasses());

        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
        self::assertSame($client, $this->recordedEvent(SessionRevoked::class)->context->client);
    }

    /**
     * Rows of `[what is presented (the carriers of the cookie token, its source
     * first, or a reason handed in, or nothing), the client, whether the
     * session is signed out, the reason, the source, whether the cookie is
     * cleared]` for a cookie application.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: non-empty-list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null, 1: \SineMacula\Laravel\Authentication\Http\ClientContext, 2: bool, 3: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 4: ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource, 5: bool}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideCookieSignOuts(): iterable
    {
        $same   = self::sameSiteClient();
        $cross  = self::crossSiteClient();
        $cookie = RefreshTokenSource::COOKIE;

        yield 'the cookie, same-site' => [[$cookie], $same, true, null, $cookie, true];
        yield 'the cookie, cross-site' => [[$cookie], $cross, false, FailureReason::CROSS_SITE_REQUEST, $cookie, false];
        yield 'the cookie twice' => [[$cookie, $cookie], $same, false, FailureReason::REFRESH_TOKEN_CONFLICT, $cookie, false];
        yield 'the body' => [[RefreshTokenSource::BODY], $same, false, FailureReason::REFRESH_TRANSPORT_MISMATCH, RefreshTokenSource::BODY, true];
        yield 'a conflict handed in' => [FailureReason::REFRESH_TOKEN_CONFLICT, $same, false, FailureReason::REFRESH_TOKEN_CONFLICT, null, false];
        yield 'a mismatch handed in' => [FailureReason::REFRESH_TRANSPORT_MISMATCH, $same, false, FailureReason::REFRESH_TRANSPORT_MISMATCH, null, true];
        yield 'a mismatch handed in, cross-site' => [FailureReason::REFRESH_TRANSPORT_MISMATCH, $cross, false, FailureReason::REFRESH_TRANSPORT_MISMATCH, null, false];
        yield 'an invalid token handed in' => [FailureReason::TOKEN_INVALID, $same, false, FailureReason::TOKEN_INVALID, null, true];
        yield 'nothing, same-site' => [null, $same, false, null, null, true];
        yield 'nothing, cross-site' => [null, $cross, false, null, null, false];
    }

    /**
     * A cookie application's sign-out from plain values signs out only a token
     * presented from its cookie by a same-site client; a refusal is reported
     * with the flow `sign_out` and the client given, and no `Failed`, and
     * leaves the session live; the result carries the expired cookie for every
     * same-site client, whether or not a session was revoked, unless its token
     * was refused as a conflict, so a cross-site page never clears it.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  bool  $signedOut
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  bool  $clears
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCookieSignOuts')]
    public function testACookieApplicationsPlainSignOutClearsTheCookieOnlyForASameSiteClient(
        array|FailureReason|null $presented,
        ClientContext $client,
        bool $signedOut,
        ?FailureReason $reason,
        ?RefreshTokenSource $source,
        bool $clears,
    ): void {
        $this->seedIdentity();

        $session  = $this->signedIn(self::BROWSER);
        $token    = self::cookieTokenOf($session);
        $sessions = $this->serving(['REMOTE_ADDR' => self::CROSS_SITE_IP], cookies: [self::COOKIE[0] => $token], guard: self::BROWSER);

        $this->recordEvents(self::EVENTS);

        $result = $sessions->signOutWith(is_array($presented) ? self::presentedToken($token, $presented[0], $presented) : $presented, $client);

        self::assertSame([$signedOut, $reason, $source], [$result->isSignedOut(), $result->reason, $result->source]);
        self::assertSame($signedOut ? 'signed_out' : null, $this->revokedReasonOf($session));

        if ($clears) {
            self::assertClears($result);
        } else {
            self::assertNull($result->forgetCookie);
            self::assertSame([], $result->attachTo(new Response)->headers->getCookies());
        }

        $expected = match (true) {
            $signedOut       => [SessionRevoked::class, Logout::class],
            $reason !== null => [AuthenticationFailed::class],
            default          => [],
        };

        self::assertSame($expected, $this->recordedClasses());

        if ($reason === null) {
            return;
        }

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::SIGN_OUT, $reason, $client], [$failure->flow, $failure->reason, $failure->context->client]);
    }

    /**
     * A body application signs out from plain values by a token presented from
     * its body field or its header with a client that has no same-site facts at
     * all, and has no cookie to clear.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABodyApplicationSignsOutFromPlainValuesWithoutSameSiteFacts(): void
    {
        $this->seedIdentity();

        foreach ([RefreshTokenSource::BODY, RefreshTokenSource::HEADER] as $source) {

            $session = $this->signedIn();
            $result  = $this->serving(['REMOTE_ADDR' => self::CROSS_SITE_IP])->signOutWith(self::presentedToken(self::refreshOf($session), $source), self::crossSiteClient());

            self::assertSame([true, $source, null], [$result->isSignedOut(), $result->source, $result->forgetCookie], $source->value);
            self::assertSame('signed_out', $this->revokedReasonOf($session));
        }

        $refused = $this->serving()->signOutWith(self::presentedToken('not-a-token', RefreshTokenSource::COOKIE), self::sameSiteClient());

        self::assertSame([FailureReason::REFRESH_TRANSPORT_MISMATCH, RefreshTokenSource::COOKIE, null], [$refused->reason, $refused->source, $refused->forgetCookie]);
        self::assertNull($this->serving()->signOutWith(null, self::sameSiteClient())->forgetCookie);
    }

    /**
     * A token presented from plain values inside the grace window still signs
     * its session out, and one replayed after it revokes the session as
     * `rotation_reuse` and is refused, both reported with the client given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGraceAndReplayHoldForAPlainSignOut(): void
    {
        $this->seedIdentity();

        $graced   = $this->signedIn(self::BROWSER);
        $replayed = $this->signedIn(self::BROWSER);
        $client   = self::sameSiteClient();

        foreach ([$graced, $replayed] as $session) {
            $presented = self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE);

            self::assertTrue($this->serving(guard: self::BROWSER)->refresh($presented, $client)->isRefreshed());
        }

        $presented = self::presentedToken(self::cookieTokenOf($graced), RefreshTokenSource::COOKIE);

        self::assertTrue($this->serving(guard: self::BROWSER)->signOutWith($presented, $client)->isSignedOut());
        self::assertSame('signed_out', $this->revokedReasonOf($graced));

        $this->moveTo(CarbonImmutable::now()->addMinutes(2));
        $this->recordEvents(self::EVENTS);

        $result = $this->serving(guard: self::BROWSER)->signOutWith(self::presentedToken(self::cookieTokenOf($replayed), RefreshTokenSource::COOKIE), $client);

        self::assertSame([false, FailureReason::ROTATION_REUSE], [$result->isSignedOut(), $result->reason]);
        self::assertClears($result);
        self::assertSame('rotation_reuse', $this->revokedReasonOf($replayed));
        self::assertSame([SessionRevoked::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(SessionRevoked::class)->context->client);
        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
    }

    /**
     * A reason the extraction never answers, handed in, is the caller's error,
     * `cross_site_request` included: it throws before anything is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReasonTheTransportNeverAnswersIsRefusedAsTheCallersError(): void
    {
        $this->recordEvents(self::EVENTS);

        foreach ([self::BROWSER, 'api'] as $guard) {
            foreach ([FailureReason::SESSION_REVOKED, FailureReason::CROSS_SITE_REQUEST] as $reason) {
                try {
                    $this->serving(guard: $guard)->signOutWith($reason, self::sameSiteClient());

                    self::fail('A sign-out took a reason the transport never answers.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertStringContainsString("`{$reason->value}`", $exception->getMessage());
                }
            }
        }

        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A plain sign-out inside the caller's transaction that rolls back revokes
     * nothing and reports no revocation: `SessionRevoked` waits on the commit,
     * while Laravel's `Logout` is dispatched at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainSignOutThatRollsBackRevokesNothing(): void
    {
        $this->seedIdentity();

        $session  = $this->signedIn(self::BROWSER);
        $sessions = $this->serving(guard: self::BROWSER);

        $this->recordEvents([SessionRevoked::class, Logout::class]);

        DB::beginTransaction();

        self::assertTrue($sessions->signOutWith(self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE), self::sameSiteClient())->isSignedOut());

        DB::rollBack();

        self::assertSame([Logout::class], $this->recordedClasses());
        self::assertNull($this->revokedReasonOf($session));
    }

    /**
     * Configure the session guards.
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

        $config->set('auth.guards.' . self::BROWSER, [
            'driver'        => 'jwt',
            'provider'      => 'identities',
            'application'   => ['methods' => ['password']],
            'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/auth']],
        ]);
    }

    /**
     * Assert the result carries the cookie application's expired cookie, and
     * attaches it alone.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignOutResult  $result
     * @param  string  $case
     * @return void
     */
    private static function assertClears(SignOutResult $result, string $case = ''): void
    {
        $cookie = $result->forgetCookie;

        self::assertNotNull($cookie, $case);
        self::assertTrue($cookie->isCleared(), $case);
        self::assertSame(self::COOKIE, [$cookie->getName(), $cookie->getPath()], $case);
        self::assertSame([$cookie], $result->attachTo(new Response)->headers->getCookies(), $case);
    }

    /**
     * The refresh token a body application's session carries.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function refreshOf(SignedInSession $session): string
    {
        $token = $session->tokens->refreshToken?->reveal();

        self::assertIsString($token);

        return $token;
    }

    /**
     * Sign a member with two memberships in as the first and switch the session
     * to the second, returning the refresh token issued before the switch.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function switchedMember(): string
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);

        $token = self::refreshOf($session);

        self::assertTrue($this->sessions('members')->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($second), self::requestClient())->isSwitched());

        return $token;
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
     * The session service of the guard, on a guard resolved afresh for a
     * sign-out request from the test client with the server values, body,
     * cookies and bearer token.
     *
     * @param  array<string, string>  $server
     * @param  array<string, string>  $body
     * @param  array<string, string>  $cookies
     * @param  ?string  $bearer
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function serving(array $server = [], array $body = [], array $cookies = [], ?string $bearer = null, string $guard = 'api'): SessionService
    {
        $server = $bearer === null ? $server : [...$server, 'HTTP_AUTHORIZATION' => 'Bearer ' . $bearer];

        app()->instance('request', Request::create('/auth/logout', 'POST', $body, $cookies, [], [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
            ...$server,
        ]));

        Auth::forgetGuards();

        return Auth::sessions($guard);
    }

    /**
     * Why the session's row records it was revoked, if it was.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return mixed
     */
    private function revokedReasonOf(SignedInSession $session): mixed
    {
        return Session::query()->whereKey($session->record->getKey())->value('revoked_reason');
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
