<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SwitchesSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Feature tests for the refresh token transport of each application, through
 * the `Auth` facade and the session service: a cookie application's sign-in,
 * start, activation by a factor or a choice, refresh and switch hand back the
 * cookie that carries the new refresh token, named after the application,
 * and never the token itself, while a body application's hand back the token;
 * a cookie application's token is read only from its cookie, by the
 * `*FromRequest()` methods, or extracted from it and handed to the
 * `*Presented()` methods with the request's client; and the cookie, the
 * application and the session must agree for a refresh to succeed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionRefresh::class)]
#[CoversClass(RefreshTokenTransport::class)]
#[CoversClass(SessionSignOut::class)]
#[CoversTrait(SwitchesSessions::class)]
final class CookieTransportTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var string The body application. */
    private const string BODY = 'api';

    /** @var string The cookie application below the root path, over the same identities. */
    private const string BROWSER = 'admin';

    /** @var string The cookie application on the root path, over members with memberships. */
    private const string MEMBERS = 'members';

    /** @var string The body application whose guard's name makes no cookie name. */
    private const string UNNAMED = 'my app';

    /** @var array<string, array{0: string, 1: string}> The cookie name and path each cookie application derives. */
    private const array COOKIES = [
        self::BROWSER => ['__Secure-admin_refresh_token', '/auth'],
        self::MEMBERS => ['__Host-members_refresh_token', '/'],
    ];

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();
    }

    /**
     * Release the clocks and drop the tables.
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
     * A cookie application's sign-in hands back the access token and the cookie
     * that carries the refresh token, under the application's own name and
     * path, expiring when the session does; a body application's hands back the
     * refresh token and no cookie.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInHandsBackTheCookieOrTheToken(): void
    {
        $this->seedIdentity();

        $cookie = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session;
        $body   = $this->sessions(self::BODY)->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($cookie);
        self::assertNotNull($body);
        self::assertCookiePair(self::BROWSER, $cookie->tokens, $cookie->record);
        self::assertNotNull($body->tokens->refreshToken);
        self::assertNull($body->tokens->refreshCookie);
    }

    /**
     * A session started for an identity verified outside the guard is handed
     * back as a sign-in is: the cookie, never the token.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStartedSessionHandsBackTheCookie(): void
    {
        $session = $this->sessions(self::BROWSER)->start(UndescribedFirstFactor::of($this->seedIdentity()), null, 'sso', self::requestContext())->session;

        self::assertNotNull($session);
        self::assertCookiePair(self::BROWSER, $session->tokens, $session->record);
    }

    /**
     * A cookie application's pending sign-in hands back its pending credential
     * in the body, never in a cookie, and the activation that satisfies its
     * factor hands back the cookie.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationByAFactorHandsBackTheCookie(): void
    {
        $identity = $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);
        self::assertNull($pending->session);

        $session = $this->sessions(self::BROWSER)->satisfy(
            $pending->credential->reveal(),
            self::adapterProof($identity, self::BROWSER, $pending->pending->id, Purpose::SIGN_IN),
            self::requestClient(),
        )->session;

        self::assertNotNull($session);
        self::assertCookiePair(self::BROWSER, $session->tokens, $session->record);
    }

    /**
     * Inside a caller's transaction the activation's result carries the cookie
     * at once, for the application to attach, while the package queues none and
     * binds the guard only once the transaction commits: a rollback leaves the
     * guard unbound with nothing queued.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationInsideATransactionQueuesNoCookieAndBindsOnCommit(): void
    {
        $identity = $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $sessions   = $this->sessions(self::BROWSER);
        $guard      = Auth::guard(self::BROWSER);
        $credential = $pending->credential->reveal();
        $proof      = self::adapterProof($identity, self::BROWSER, $pending->pending->id, Purpose::SIGN_IN);

        DB::beginTransaction();

        $session = $sessions->satisfy($credential, $proof, self::requestClient())->session;

        self::assertNotNull($session);
        self::assertNotNull($session->tokens->refreshCookie);
        self::assertFalse($guard->hasUser());

        DB::rollBack();

        self::assertFalse($guard->hasUser());
        self::assertSame([], app('cookie')->getQueuedCookies());

        $committed = DB::transaction(static fn (): ?SignedInSession => $sessions->satisfy($credential, $proof, self::requestClient())->session);

        self::assertNotNull($committed);
        self::assertCookiePair(self::BROWSER, $committed->tokens, $committed->record);
        self::assertTrue($guard->hasUser());
        self::assertSame([], app('cookie')->getQueuedCookies());
    }

    /**
     * The activation that makes a cookie application's choice of principal
     * hands back the cookie, on the root path under a `__Host-` name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationByAChoiceHandsBackTheCookie(): void
    {
        [$member, $first] = $this->seedMember();

        $other = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);

        ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $pending = $this->sessions(self::MEMBERS)->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertNotNull($pending->credential);

        $session = $this->sessions(self::MEMBERS)->choose($pending->credential->reveal(), $first, self::requestClient())->session;

        self::assertNotNull($session);
        self::assertCookiePair(self::MEMBERS, $session->tokens, $session->record);
    }

    /**
     * A cookie application whose transport is misconfigured (here, its
     * `cookie.path` taken away) fails a sign-in, a start and an activation by a
     * factor or a choice before anything is written or reported: no session is
     * created, no event is dispatched, and the pending credential is not spent,
     * so the activation succeeds once the configuration is fixed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMisconfiguredTransportFailsBeforeAnythingIsWrittenOrReported(): void
    {
        $identity = $this->seedIdentity();

        [$member, $first] = $this->seedMember();

        $other = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);

        ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $choice = $this->sessions(self::MEMBERS)->signIn('password', self::credentials('member@example.test'), self::requestContext());

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $factor = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($choice->credential);
        self::assertNotNull($factor->pending);
        self::assertNotNull($factor->credential);

        $proof = self::adapterProof($identity, self::BROWSER, $factor->pending->id, Purpose::SIGN_IN);
        $rows  = Session::query()->count();

        config()->set('auth.guards.' . self::BROWSER . '.refresh_token.cookie.path', null);
        config()->set('auth.guards.' . self::MEMBERS . '.refresh_token.cookie.path', null);

        $this->recordEvents([Attempting::class, SessionCreated::class, SessionPending::class, SessionActivated::class, SignedIn::class, AuthenticationFailed::class]);

        $calls = [
            self::BROWSER => [
                fn (): mixed => $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext()),
                fn (): mixed => $this->sessions(self::BROWSER)->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext()),
                fn (): mixed => $this->sessions(self::BROWSER)->satisfy($factor->credential->reveal(), $proof, self::requestClient()),
            ],
            self::MEMBERS => [
                fn (): mixed => $this->sessions(self::MEMBERS)->choose($choice->credential->reveal(), $first, self::requestClient()),
            ],
        ];

        foreach ($calls as $guard => $guardCalls) {
            foreach ($guardCalls as $call) {
                try {
                    $call();

                    self::fail('A sign-in went ahead with a misconfigured transport.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertStringStartsWith("Refresh token transport for guard [{$guard}]: `refresh_token.cookie.path`", $exception->getMessage());
                }
            }
        }

        self::assertSame([], $this->recordedClasses());
        self::assertSame($rows, Session::query()->count());

        config()->set('auth.guards.' . self::BROWSER . '.refresh_token.cookie.path', '/auth');
        config()->set('auth.guards.' . self::MEMBERS . '.refresh_token.cookie.path', '/');

        self::assertTrue($this->sessions(self::BROWSER)->satisfy($factor->credential->reveal(), $proof, self::requestClient())->isSignedIn());

        app()->instance(AdditionalFactorPolicy::class, new NeverRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        self::assertTrue($this->sessions(self::MEMBERS)->choose($choice->credential->reveal(), $first, self::requestClient())->isSignedIn());
    }

    /**
     * A refresh read from a cookie application's cookie rotates the session and
     * hands back the cookie with the new token, never the token, and the new
     * cookie refreshes again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshFromTheCookieHandsBackTheNewCookie(): void
    {
        $this->seedIdentity();

        $first = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session?->tokens;

        self::assertNotNull($first);

        $refreshed = $this->fromCookie(self::BROWSER, self::cookieValue($first))->refresh(self::servedToken(self::BROWSER), self::requestClient());

        self::assertNotNull($refreshed);
        self::assertTrue($refreshed->isRefreshed());
        self::assertSame(RefreshTokenSource::COOKIE, $refreshed->source);
        self::assertNotNull($refreshed->session);
        self::assertCookiePair(self::BROWSER, $refreshed->session->tokens, $refreshed->session->record);
        self::assertNotSame(self::cookieValue($first), self::cookieValue($refreshed->session->tokens));
        self::assertTrue(
            $this->fromCookie(self::BROWSER, self::cookieValue($refreshed->session->tokens))->refresh(self::servedToken(self::BROWSER), self::requestClient())?->isRefreshed(),
        );
    }

    /**
     * A switch read from a cookie application's cookie hands back the cookie
     * with the new token, never the token.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchFromTheCookieHandsBackTheNewCookie(): void
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);
        $tokens = $this->sessions(self::MEMBERS)->signIn(
            'password',
            self::credentials('member@example.test'),
            SignInContext::fromRequest(request(), principal: $first),
        )->session?->tokens;

        self::assertNotNull($tokens);

        $switched = $this->fromCookie(self::MEMBERS, self::cookieValue($tokens))->switchTo(
            self::servedToken(self::MEMBERS),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertNotNull($switched);
        self::assertTrue($switched->isSwitched());
        self::assertSame(RefreshTokenSource::COOKIE, $switched->source);
        self::assertNotNull($switched->session);
        self::assertSame($second->getPrincipalIdentifier(), $switched->session->principal->getPrincipalIdentifier());
        self::assertCookiePair(self::MEMBERS, $switched->session->tokens, $switched->session->record);
    }

    /**
     * Inside a caller's transaction a refresh's result carries the new cookie
     * at once, for the application to attach, while the package queues none and
     * binds the guard only once the transaction commits, once: a rollback
     * leaves the guard unbound with nothing queued, and the old cookie still
     * refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshInsideATransactionQueuesNoCookieAndBindsOnCommit(): void
    {
        $this->seedIdentity();

        $first = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session?->tokens;
        $binds = $this->countBinds();

        self::assertNotNull($first);

        $sessions = $this->fromCookie(self::BROWSER, self::cookieValue($first));
        $guard    = app('auth')->guard(self::BROWSER);

        DB::beginTransaction();

        $refreshed = $sessions->refresh(self::servedToken(self::BROWSER), self::requestClient())?->session;

        self::assertNotNull($refreshed);
        self::assertNotNull($refreshed->tokens->refreshCookie);
        self::assertFalse($guard->hasUser());

        DB::rollBack();

        self::assertCount(0, $binds);
        self::assertFalse($guard->hasUser());
        self::assertSame([], app('cookie')->getQueuedCookies());

        $sessions  = $this->fromCookie(self::BROWSER, self::cookieValue($first));
        $guard     = app('auth')->guard(self::BROWSER);
        $committed = DB::transaction(static fn (): ?SignedInSession => $sessions->refresh(self::servedToken(self::BROWSER), self::requestClient())?->session);

        self::assertNotNull($committed);
        self::assertCookiePair(self::BROWSER, $committed->tokens, $committed->record);
        self::assertCount(1, $binds);
        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertSame($committed->record->getKey(), $guard->session()?->getSessionIdentifier());
        self::assertSame([], app('cookie')->getQueuedCookies());
    }

    /**
     * Inside a caller's transaction a switch's result carries the new cookie at
     * once, while the package queues none and binds the guard to the
     * destination only once the transaction commits, once: a rollback leaves
     * the guard unbound with nothing queued and the session as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchInsideATransactionQueuesNoCookieAndBindsOnCommit(): void
    {
        [$member, $first] = $this->seedMember();

        $other   = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);
        $members = $this->sessions(self::MEMBERS);
        $context = SignInContext::fromRequest(request(), principal: $first);
        $tokens  = $members->signIn('password', self::credentials('member@example.test'), $context)->session?->tokens;
        $binds   = $this->countBinds();

        self::assertNotNull($tokens);

        $sessions = $this->fromCookie(self::MEMBERS, self::cookieValue($tokens));
        $guard    = app('auth')->guard(self::MEMBERS);

        DB::beginTransaction();

        $switched = $sessions->switchTo(self::servedToken(self::MEMBERS), SwitchTarget::principal($second), self::requestClient())?->session;

        self::assertNotNull($switched);
        self::assertNotNull($switched->tokens->refreshCookie);
        self::assertFalse($guard->hasUser());

        DB::rollBack();

        self::assertCount(0, $binds);
        self::assertFalse($guard->hasUser());
        self::assertSame([], app('cookie')->getQueuedCookies());
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify(Session::query()->value('principal_id')));

        $sessions  = $this->fromCookie(self::MEMBERS, self::cookieValue($tokens));
        $guard     = app('auth')->guard(self::MEMBERS);
        $committed = DB::transaction(
            static fn (): ?SignedInSession => $sessions->switchTo(self::servedToken(self::MEMBERS), SwitchTarget::principal($second), self::requestClient())?->session,
        );

        self::assertNotNull($committed);
        self::assertCookiePair(self::MEMBERS, $committed->tokens, $committed->record);
        self::assertCount(1, $binds);
        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertSame($second->getPrincipalIdentifier(), $guard->principal()?->getPrincipalIdentifier());
        self::assertSame([], app('cookie')->getQueuedCookies());
    }

    /**
     * A cookie application refuses a refresh token its own code read from a
     * body and handed in, to refresh, to switch or to sign out, as
     * `refresh_transport_mismatch`, reported as each action reports a refusal
     * and touching no session: its token travels only in its cookie, with the
     * cookie's cross-site checks. A body application takes one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationRefusesATokenFromTheBody(): void
    {
        $this->seedIdentity();

        $token = self::cookieValue($this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session?->tokens);
        $other = $this->seedIdentity('grace@example.test');

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class]);

        $refreshed = $this->sessions(self::BROWSER)->refresh(PresentedRefreshToken::fromBody($token), self::sameSiteClient());

        self::assertSame([Attempting::class, Failed::class, AuthenticationFailed::class], $this->recordedClasses());

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class]);

        $switched = $this->sessions(self::BROWSER)->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($other), self::sameSiteClient());

        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class]);

        $signedOut = $this->sessions(self::BROWSER)->signOutWith(PresentedRefreshToken::fromBody($token), self::sameSiteClient());

        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());

        foreach ([$refreshed, $switched, $signedOut] as $result) {
            self::assertSame(FailureReason::REFRESH_TRANSPORT_MISMATCH, $result->reason);
            self::assertSame(RefreshTokenSource::BODY, $result->source);
        }

        self::assertSame(AuthenticationFlow::SIGN_OUT, $this->recordedEvent(AuthenticationFailed::class)->flow);
        self::assertTrue($this->fromCookie(self::BROWSER, $token)->refresh(self::servedToken(self::BROWSER), self::requestClient())?->isRefreshed());

        $body = $this->sessions(self::BODY)->signIn('password', self::credentials(), self::requestContext())->session?->tokens->refreshToken;

        self::assertNotNull($body);
        self::assertTrue($this->sessions(self::BODY)->refresh(PresentedRefreshToken::fromBody($body), self::requestClient())->isRefreshed());
    }

    /**
     * A controller that keeps HTTP out of its service layer extracts the token
     * from the cookie and hands it on with the request's client: the service
     * refreshes from those plain values and the response sets the new cookie,
     * which a later request extracts and signs out by, the response clearing
     * the cookie. The same request sent from another site extracts the token
     * all the same, and the plain refresh refuses it as `cross_site_request`,
     * as the request form does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAControllerExtractsTheCookieAndTheServiceRefreshesAndSignsOutFromPlainValues(): void
    {
        $this->seedIdentity();

        $first     = self::cookieValue($this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session?->tokens);
        $transport = Auth::refreshTransport(self::BROWSER);

        $this->fromCookie(self::BROWSER, $first);

        $request   = request();
        $refreshed = Auth::sessions(self::BROWSER)->refresh($transport->extract($request), ClientContext::fromRequest($request));

        self::assertNotNull($refreshed);
        self::assertSame(RefreshTokenSource::COOKIE, $refreshed->source);
        self::assertNotNull($refreshed->session);
        self::assertCookiePair(self::BROWSER, $refreshed->session->tokens, $refreshed->session->record);

        $set = $refreshed->session->tokens->refreshCookie?->attachTo(new Response)->headers->getCookies();

        self::assertNotNull($set);
        self::assertCount(1, $set);
        self::assertSame(self::cookieValue($refreshed->session->tokens), $set[0]->getValue());

        $value     = $set[0]->getValue();
        $crossSite = Request::create('/auth/refresh', 'POST', [], [self::COOKIES[self::BROWSER][0] => $value], [], [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
        ]);

        $refused = Auth::sessions(self::BROWSER)->refresh($transport->extract($crossSite), ClientContext::fromRequest($crossSite));

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $refused?->reason);
        self::assertIsString($value);

        $this->fromCookie(self::BROWSER, $value);

        $request = request();
        $signOut = Auth::sessions(self::BROWSER)->signOutWith($transport->extract($request), ClientContext::fromRequest($request));

        self::assertTrue($signOut->isSignedOut());
        self::assertSame(RefreshTokenSource::COOKIE, $signOut->source);

        $cleared = $signOut->attachTo(new Response)->headers->getCookies();

        self::assertCount(1, $cleared);
        self::assertTrue($cleared[0]->isCleared());
        self::assertSame(self::COOKIES[self::BROWSER], [$cleared[0]->getName(), $cleared[0]->getPath()]);
        self::assertSame('signed_out', Session::query()->whereKey($refreshed->session->record->getKey())->value('revoked_reason'));
    }

    /**
     * A cookie application's sign-out reads the token from its cookie and
     * revokes the session it proves, and its result carries the expired cookie,
     * under the application's name and path, for a request the application's
     * own pages sent: when the cookie signed the session out, when a same-site
     * request sent no cookie, and when a live access token signed its session
     * out. A request that fails the cookie's same-site checks clears nothing:
     * one without the custom header that sent the cookie (`cross_site_request`,
     * the session left live), one from another site that sent none (as a
     * browser withholds a `SameSite=Strict` cookie from a cross-site form), and
     * a same-site one that sent the token twice (`refresh_token_conflict`).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationsSignOutClearsTheCookieOnlyForItsOwnPages(): void
    {
        $this->seedIdentity();

        $byCookie = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session;
        $byBearer = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($byCookie);
        self::assertNotNull($byBearer);

        $value = self::cookieValue($byCookie->tokens);

        app()->instance('request', Request::create('/auth/logout', 'POST', [], [self::COOKIES[self::BROWSER][0] => $value], [], [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
            'HTTP_ORIGIN'     => 'http://localhost',
        ]));

        Auth::forgetGuards();

        $crossSite = self::signOutServed(Auth::sessions(self::BROWSER), self::BROWSER);

        app()->instance('request', Request::create('/auth/logout', 'POST', server: [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
            'HTTP_ORIGIN'     => 'https://elsewhere.example',
        ]));

        Auth::forgetGuards();

        $fromElsewhere = self::signOutServed(Auth::sessions(self::BROWSER), self::BROWSER);
        $conflict      = self::signOutServed($this->request(self::BROWSER, ['refresh_token' => $value], [self::COOKIES[self::BROWSER][0] => $value]), self::BROWSER);

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $crossSite->reason);
        self::assertFalse($fromElsewhere->isSignedOut());
        self::assertFalse($fromElsewhere->isFailed());
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $conflict->reason);
        self::assertNull(Session::query()->whereKey($byCookie->record->getKey())->value('revoked_at'));

        foreach ([$crossSite, $fromElsewhere, $conflict] as $result) {
            self::assertNull($result->forgetCookie);
            self::assertSame([], $result->attachTo(new Response)->headers->getCookies());
        }

        app()->instance('request', Request::create('/auth/logout', 'POST', server: [
            'REMOTE_ADDR'        => self::CLIENT_IP,
            'HTTP_AUTHORIZATION' => 'Bearer ' . $byBearer->tokens->accessToken->reveal(),
        ]));

        Auth::forgetGuards();

        $bearer  = self::signOutServed(Auth::sessions(self::BROWSER), self::BROWSER);
        $signed  = self::signOutServed($this->fromCookie(self::BROWSER, $value), self::BROWSER);
        $nothing = self::signOutServed($this->request(self::BROWSER), self::BROWSER);

        self::assertTrue($signed->isSignedOut());
        self::assertSame(RefreshTokenSource::COOKIE, $signed->source);
        self::assertTrue($bearer->isSignedOut());
        self::assertNull($bearer->source);
        self::assertFalse($nothing->isSignedOut());
        self::assertFalse($nothing->isFailed());
        self::assertSame('signed_out', Session::query()->whereKey($byCookie->record->getKey())->value('revoked_reason'));
        self::assertSame('signed_out', Session::query()->whereKey($byBearer->record->getKey())->value('revoked_reason'));

        foreach ([$bearer, $signed, $nothing] as $result) {

            $cookie = $result->forgetCookie;

            self::assertNotNull($cookie);
            self::assertTrue($cookie->isCleared());
            self::assertSame(self::COOKIES[self::BROWSER], [$cookie->getName(), $cookie->getPath()]);
            self::assertSame([$cookie], $result->attachTo(new Response)->headers->getCookies());
        }
    }

    /**
     * A same-site sign-out whose cookie proves no live session still clears the
     * dead cookie from the browser, under the application's name and path: a
     * cookie whose session is already revoked (`session_revoked`), a token the
     * application's pages sent in the body instead
     * (`refresh_transport_mismatch`), and a replayed cookie, which revokes its
     * session as `rotation_reuse`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationsSignOutClearsADeadCookieForItsOwnPages(): void
    {
        $this->seedIdentity();

        $revoked  = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session;
        $replayed = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($revoked);
        self::assertNotNull($replayed);

        $value    = self::cookieValue($revoked->tokens);
        $replaced = self::cookieValue($replayed->tokens);

        self::assertTrue(self::signOutServed($this->fromCookie(self::BROWSER, $value), self::BROWSER)->isSignedOut());
        self::assertTrue((bool) $this->fromCookie(self::BROWSER, $replaced)->refresh(self::servedToken(self::BROWSER), self::requestClient())?->isRefreshed());

        $later = CarbonImmutable::now()->addMinutes(2);

        Carbon::setTestNow($later);
        CarbonImmutable::setTestNow($later);

        JWT::$timestamp = $later->getTimestamp();

        $results = [
            'session_revoked'            => self::signOutServed($this->fromCookie(self::BROWSER, $value), self::BROWSER),
            'refresh_transport_mismatch' => self::signOutServed($this->request(self::BROWSER, ['refresh_token' => $value]), self::BROWSER),
            'rotation_reuse'             => self::signOutServed($this->fromCookie(self::BROWSER, $replaced), self::BROWSER),
        ];

        self::assertSame('rotation_reuse', Session::query()->whereKey($replayed->record->getKey())->value('revoked_reason'));

        foreach ($results as $reason => $result) {

            $cookie = $result->forgetCookie;

            self::assertFalse($result->isSignedOut(), $reason);
            self::assertSame($reason, $result->reason?->value);
            self::assertNotNull($cookie, $reason);
            self::assertTrue($cookie->isCleared(), $reason);
            self::assertSame(self::COOKIES[self::BROWSER], [$cookie->getName(), $cookie->getPath()], $reason);
            self::assertSame([$cookie], $result->attachTo(new Response)->headers->getCookies(), $reason);
        }
    }

    /**
     * A cookie application's sign-out that finds nothing left to revoke still
     * clears the cookie, under the application's name and path: a guard bound
     * to a session revoked since, and a cookie whose session another writer
     * revokes between the proof's read and the sign-out's write.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationsSignOutClearsTheCookieWhenNothingIsLeftToRevoke(): void
    {
        $this->seedIdentity();

        $bound = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session;
        $raced = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($bound);
        self::assertNotNull($raced);

        Session::query()->whereKey($bound->record->getKey())->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);

        $guard = $this->freshGuard(self::BROWSER);

        $guard->setSession(Session::query()->findOrFail($bound->record->getKey()));

        $results = ['bound' => self::signOutServed(self::sessionsOf($guard), self::BROWSER)];
        $armed   = new \ArrayObject(['armed' => true]);
        $service = $this->fromCookie(self::BROWSER, self::cookieValue($raced->tokens));

        DB::listen(static function (QueryExecuted $query) use ($armed): void {

            if ($armed['armed'] !== true || !str_starts_with(strtolower(ltrim($query->sql)), 'select') || !str_contains($query->sql, 'authentication_sessions')) {
                return;
            }

            $armed['armed'] = false;

            DB::table('authentication_sessions')->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);
        });

        $results['raced'] = self::signOutServed($service, self::BROWSER);

        self::assertFalse($armed['armed']);
        self::assertSame('revoked', Session::query()->whereKey($raced->record->getKey())->value('revoked_reason'));

        foreach ($results as $case => $result) {

            $cookie = $result->forgetCookie;

            self::assertFalse($result->isSignedOut(), $case);
            self::assertFalse($result->isFailed(), $case);
            self::assertNotNull($cookie, $case);
            self::assertTrue($cookie->isCleared(), $case);
            self::assertSame(self::COOKIES[self::BROWSER], [$cookie->getName(), $cookie->getPath()], $case);
            self::assertSame([$cookie], $result->attachTo(new Response)->headers->getCookies(), $case);
        }
    }

    /**
     * A body application whose guard's name makes no cookie name needs no
     * cookie configuration and looks for no cookie of its own: through the
     * session service it signs in with the refresh token in its pair, refreshes
     * from the body while a stray cookie rides along, neither refused as the
     * wrong transport nor in conflict, and signs out by the body with nothing
     * to clear.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABodyApplicationWhoseNameMakesNoCookieNameSignsInRefreshesAndSignsOut(): void
    {
        $this->seedIdentity();

        $session = $this->sessions(self::UNNAMED)->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);
        self::assertNull($session->tokens->refreshCookie);

        $token = $session->tokens->refreshToken;

        self::assertNotNull($token);

        $stray     = ['__Secure-my_app_refresh_token' => 'stray', '__Secure-api_refresh_token' => 'stray'];
        $refreshed = $this->request(self::UNNAMED, ['refresh_token' => $token->reveal()], $stray)->refresh(self::servedToken(self::UNNAMED), self::requestClient());

        self::assertNotNull($refreshed);
        self::assertTrue($refreshed->isRefreshed());
        self::assertSame(RefreshTokenSource::BODY, $refreshed->source);

        $rotated = $refreshed->session?->tokens->refreshToken;

        self::assertNotNull($rotated);

        $signedOut = self::signOutServed($this->request(self::UNNAMED, ['refresh_token' => $rotated->reveal()], $stray), self::UNNAMED);

        self::assertTrue($signedOut->isSignedOut());
        self::assertSame(RefreshTokenSource::BODY, $signedOut->source);
        self::assertNull($signedOut->forgetCookie);
        self::assertSame('signed_out', Session::query()->whereKey($session->record->getKey())->value('revoked_reason'));
    }

    /**
     * The cookie, the application and the session must agree: another
     * application's cookie is not this one's (nothing is read); this
     * application's cookie carrying another application's token fails the
     * token's `client_id` (`token_invalid`); a token of this application for a
     * session of another (`session_guard_mismatch`) is refused without touching
     * that session; and a cookie to a body application, or the body to a cookie
     * application, is the wrong transport.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCookieTheApplicationAndTheSessionMustAgree(): void
    {
        $this->seedIdentity();

        $body    = $this->sessions(self::BODY)->signIn('password', self::credentials(), self::requestContext())->session;
        $browser = $this->sessions(self::BROWSER)->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($body);
        self::assertNotNull($browser);

        $other = (string) $body->tokens->refreshToken?->reveal();

        self::assertNull($this->request(self::BROWSER, cookies: ['__Secure-api_refresh_token' => $other])->refresh(self::servedToken(self::BROWSER), self::requestClient()));
        self::assertSame(FailureReason::TOKEN_INVALID, $this->fromCookie(self::BROWSER, $other)->refresh(self::servedToken(self::BROWSER), self::requestClient())?->reason);

        $crossed = Auth::jwt(self::BROWSER)->issueRefreshToken($body->record, 'rotation-of-the-api-session', $body->principal)->reveal();
        $before  = Session::query()->whereKey($body->record->getKey())->sole()->getAttributes();

        self::assertSame(
            FailureReason::SESSION_GUARD_MISMATCH,
            $this->fromCookie(self::BROWSER, $crossed)->refresh(self::servedToken(self::BROWSER), self::requestClient())?->reason,
        );
        self::assertSame($before, Session::query()->whereKey($body->record->getKey())->sole()->getAttributes());

        self::assertSame(
            FailureReason::REFRESH_TRANSPORT_MISMATCH,
            $this->request(self::BODY, cookies: ['__Secure-api_refresh_token' => $other])->refresh(self::servedToken(self::BODY), self::requestClient())?->reason,
        );
        self::assertSame(
            FailureReason::REFRESH_TRANSPORT_MISMATCH,
            $this->request(self::BROWSER, ['refresh_token' => self::cookieValue($browser->tokens)])->refresh(self::servedToken(self::BROWSER), self::requestClient())?->reason,
        );
    }

    /**
     * Configure the guards: `api` keeps the body transport, as does `my app`,
     * whose name makes no cookie name, `admin` travels by cookie under `/auth`,
     * and `members` by cookie on the root path.
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

        $config->set('auth.guards.' . self::UNNAMED, ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]]);
        $config->set('auth.guards.' . self::BROWSER . '.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);
        $config->set('auth.guards.' . self::MEMBERS . '.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/']]);
    }

    /**
     * Assert the pair is a cookie application's: the access token, no refresh
     * token, and the cookie with the application's name and path, carrying a
     * refresh token for the session that expires when the session ends.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @return void
     */
    private static function assertCookiePair(string $guard, TokenPair $tokens, EloquentSession&Model $record): void
    {
        self::assertNull($tokens->refreshToken);
        self::assertNotNull($tokens->refreshCookie);
        self::assertSame(self::COOKIES[$guard], [$tokens->refreshCookie->name, $tokens->refreshCookie->path]);

        $claims = Auth::jwt($guard)->parse(self::cookieValue($tokens));

        self::assertIsArray($claims);
        self::assertSame(IdentifierCoercion::stringify($record->getSessionIdentifier()), $claims['sid'] ?? null);
        self::assertSame($claims['exp'] ?? null, $tokens->refreshCookie->expiresAt->getTimestamp());
        self::assertNotNull(Auth::jwt($guard)->parse($tokens->accessToken));
    }

    /**
     * The refresh token a cookie application's pair carries in its cookie.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @return string
     */
    private static function cookieValue(?TokenPair $tokens): string
    {
        $value = $tokens?->refreshCookie?->cookie()->getValue();

        self::assertIsString($value);

        return $value;
    }

    /**
     * Count the binds from here on, by the `SessionAuthenticated` each
     * dispatches.
     *
     * @return \ArrayObject<int, \SineMacula\Laravel\Authentication\Events\SessionAuthenticated>
     */
    private function countBinds(): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Events\SessionAuthenticated> $binds */
        $binds = new \ArrayObject;

        Event::listen(SessionAuthenticated::class, static function (SessionAuthenticated $event) use ($binds): void {
            $binds->append($event);
        });

        return $binds;
    }

    /**
     * The session service of the cookie application, for a same-site request
     * carrying the token in its cookie.
     *
     * @param  string  $guard
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function fromCookie(string $guard, #[\SensitiveParameter] string $token): SessionService
    {
        return $this->request($guard, cookies: [self::COOKIES[$guard][0] => $token]);
    }

    /**
     * The session service of the guard, for a same-site refresh request with
     * the form body and cookies.
     *
     * @param  string  $guard
     * @param  array<string, string>  $body
     * @param  array<string, string>  $cookies
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function request(string $guard, array $body = [], array $cookies = []): SessionService
    {
        app()->instance('request', Request::create('/auth/refresh', 'POST', $body, $cookies, [], [
            'REMOTE_ADDR'           => self::CLIENT_IP,
            'HTTP_USER_AGENT'       => self::CLIENT_AGENT,
            'HTTP_ORIGIN'           => 'http://localhost',
            'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
        ]));

        Auth::forgetGuards();

        return Auth::sessions($guard);
    }
}
