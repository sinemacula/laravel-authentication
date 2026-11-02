<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Logout;
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
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignOutResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Feature tests of signing out by whichever credential the request carries, on
 * a body application: a request bound to its session by a live access token is
 * signed out as `signOut()` signs it out; otherwise its binding is forgotten
 * and the session its refresh token proves is revoked, so a client whose access
 * token expired, or that holds none, still signs out; a refused refresh token
 * signs the request out all the same and is reported with the flow `sign_out`
 * and its reason, and never as a failed authentication.
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

        $result = $sessions->signOutFromRequest();

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

        $result = $sessions->signOutFromRequest();

        self::assertFalse($result->isSignedOut());
        self::assertFalse($result->isFailed());
        self::assertNull($result->source);
        self::assertSame([Logout::class], $this->recordedClasses());
        self::assertTrue($identity->is($this->recordedEvent(Logout::class)->user));
        self::assertFalse(Auth::guard('api')->check());
    }

    /**
     * An access-only token with a refresh token signs the session the refresh
     * token proves out, and `Logout` fires once, for the forgotten binding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccessOnlyTokenWithARefreshTokenSignsItsSessionOutWithOneLogout(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $sessions = $this->serving(
            bearer: Auth::jwt('api')->issueAccessToken($identity, $identity, null, null)->reveal(),
            body: ['refresh_token' => self::refreshOf($session)],
        );

        $this->recordEvents(self::EVENTS);

        $result = $sessions->signOutFromRequest();

        self::assertTrue($result->isSignedOut());
        self::assertSame(RefreshTokenSource::BODY, $result->source);
        self::assertSame([Logout::class, SessionRevoked::class], $this->recordedClasses());
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

        $result = $sessions->signOutFromRequest();

        self::assertTrue($result->isSignedOut());
        self::assertSame($source, $result->source);
        self::assertNull($result->reason);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::SIGNED_OUT, $revoked->reason);
        self::assertSame(['api', 'password'], [$revoked->context->guard, $revoked->context->method]);
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), $revoked->context->sessionId);
        self::assertTrue($identity->is($revoked->context->identity));
        self::assertTrue($identity->is($this->recordedEvent(Logout::class)->user));
        self::assertSame('api', $this->recordedEvent(Logout::class)->guard);
        self::assertSame('signed_out', $this->revokedReasonOf($session));
        self::assertSame(FailureReason::SESSION_REVOKED, $this->sessions()->refresh(self::refreshOf($session))->reason);
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

        $result = $this->serving()->signOutFromRequest();

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

        self::assertTrue($this->sessions()->refresh(self::refreshOf($replayed))->isRefreshed());

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

            $result = $sessions->signOutFromRequest();

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

            $result = $sessions->signOutFromRequest();

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

        self::assertTrue($sessions->signOutFromRequest()->isSignedOut());
        self::assertSame([SessionRevoked::class], $this->recordedClasses());

        $context = $this->recordedEvent(SessionRevoked::class)->context;

        self::assertNull($context->identity);
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

        $result = self::sessionsOf($guard)->signOutFromRequest();

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

        $elsewhere = $sessions->signOutWith(self::refreshOf($other));

        self::assertTrue($elsewhere->isSignedOut());
        self::assertNull($elsewhere->source);
        self::assertNull($elsewhere->forgetCookie);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertTrue(Auth::guard('api')->check());

        $this->recordEvents(self::EVENTS);

        self::assertTrue($sessions->signOutWith(self::refreshOf($current))->isSignedOut());
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertTrue($identity->is($this->recordedEvent(Logout::class)->user));
        self::assertTrue(Auth::guard('api')->guest());
        self::assertSame('signed_out', $this->revokedReasonOf($current));
        self::assertSame('signed_out', $this->revokedReasonOf($other));
    }

    /**
     * A token handed in that proves no session is refused with its reason and
     * no source, reported with the flow `sign_out`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenHandedInThatProvesNoSessionIsRefused(): void
    {
        $this->recordEvents(self::EVENTS);

        $result = $this->serving()->signOutWith('not-a-token');

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::TOKEN_INVALID, $result->reason);
        self::assertNull($result->source);
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
            self::assertSame(FailureReason::TOKEN_INVALID, $this->serving()->signOutWith('not-a-token-' . $attempt)->reason);
        }

        self::assertTrue($this->serving()->signOutWith(self::refreshOf($session))->isSignedOut());
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
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

        self::assertTrue($this->sessions('members')->switchTo($token, SwitchTarget::principal($second))->isSwitched());

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
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

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
