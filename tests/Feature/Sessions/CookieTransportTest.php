<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SwitchesSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
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
 * `*FromRequest()` methods; and the cookie, the application and the session
 * must agree for a refresh to succeed.
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

        $cookie = $this->sessions(self::BROWSER)->signIn('password', self::credentials())->session;
        $body   = $this->sessions(self::BODY)->signIn('password', self::credentials())->session;

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
        $session = $this->sessions(self::BROWSER)->start($this->seedIdentity(), null, 'sso')->session;

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

        $pending = $this->sessions(self::BROWSER)->signIn('password', self::credentials());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);
        self::assertNull($pending->session);

        $session = $this->sessions(self::BROWSER)->satisfy(
            $pending->credential->reveal(),
            self::adapterProof($identity, self::BROWSER, $pending->pending->id, Purpose::SIGN_IN),
        )->session;

        self::assertNotNull($session);
        self::assertCookiePair(self::BROWSER, $session->tokens, $session->record);
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

        $pending = $this->sessions(self::MEMBERS)->signIn('password', self::credentials('member@example.test'));

        self::assertNotNull($pending->credential);

        $session = $this->sessions(self::MEMBERS)->choose($pending->credential->reveal(), $first)->session;

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

        $choice = $this->sessions(self::MEMBERS)->signIn('password', self::credentials('member@example.test'));

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $factor = $this->sessions(self::BROWSER)->signIn('password', self::credentials());

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
                fn (): mixed => $this->sessions(self::BROWSER)->signIn('password', self::credentials()),
                fn (): mixed => $this->sessions(self::BROWSER)->start($identity, null, 'sso'),
                fn (): mixed => $this->sessions(self::BROWSER)->satisfy($factor->credential->reveal(), $proof),
            ],
            self::MEMBERS => [
                fn (): mixed => $this->sessions(self::MEMBERS)->choose($choice->credential->reveal(), $first),
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

        self::assertTrue($this->sessions(self::BROWSER)->satisfy($factor->credential->reveal(), $proof)->isSignedIn());

        app()->instance(AdditionalFactorPolicy::class, new NeverRequireAdditionalFactor);

        self::assertTrue($this->sessions(self::MEMBERS)->choose($choice->credential->reveal(), $first)->isSignedIn());
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

        $first = $this->sessions(self::BROWSER)->signIn('password', self::credentials())->session?->tokens;

        self::assertNotNull($first);

        $refreshed = $this->fromCookie(self::BROWSER, self::cookieValue($first))->refreshFromRequest();

        self::assertNotNull($refreshed);
        self::assertTrue($refreshed->isRefreshed());
        self::assertSame(RefreshTokenSource::COOKIE, $refreshed->source);
        self::assertNotNull($refreshed->session);
        self::assertCookiePair(self::BROWSER, $refreshed->session->tokens, $refreshed->session->record);
        self::assertNotSame(self::cookieValue($first), self::cookieValue($refreshed->session->tokens));
        self::assertTrue($this->fromCookie(self::BROWSER, self::cookieValue($refreshed->session->tokens))->refreshFromRequest()?->isRefreshed());
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

        $switched = $this->fromCookie(self::MEMBERS, self::cookieValue($tokens))->switchFromRequest(SwitchTarget::principal($second));

        self::assertNotNull($switched);
        self::assertTrue($switched->isSwitched());
        self::assertSame(RefreshTokenSource::COOKIE, $switched->source);
        self::assertNotNull($switched->session);
        self::assertSame($second->getPrincipalIdentifier(), $switched->session->principal->getPrincipalIdentifier());
        self::assertCookiePair(self::MEMBERS, $switched->session->tokens, $switched->session->record);
    }

    /**
     * A cookie application refuses a refresh token its own code read and handed
     * in, to refresh, to switch or to sign out, before anything is attempted:
     * its token is read only from its cookie, with the cookie's cross-site
     * checks. A body application takes one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationRefusesATokenHandedIn(): void
    {
        $this->seedIdentity();

        $token = self::cookieValue($this->sessions(self::BROWSER)->signIn('password', self::credentials())->session?->tokens);
        $other = $this->seedIdentity('grace@example.test');

        $this->recordEvents([Attempting::class, AuthenticationFailed::class]);

        $calls = [
            fn (): mixed => $this->sessions(self::BROWSER)->refresh($token),
            fn (): mixed => $this->sessions(self::BROWSER)->switchTo($token, SwitchTarget::principal($other)),
            fn (): mixed => $this->sessions(self::BROWSER)->signOutWith($token),
        ];

        foreach ($calls as $call) {
            try {
                $call();

                self::fail('A cookie application took a refresh token handed in.');
            } catch (\LogicException $exception) {
                self::assertSame(SessionRefresh::COOKIE_ONLY, $exception->getMessage());
            }
        }

        self::assertSame([], $this->recordedClasses());

        $body = $this->sessions(self::BODY)->signIn('password', self::credentials())->session?->tokens->refreshToken;

        self::assertNotNull($body);
        self::assertTrue($this->sessions(self::BODY)->refresh($body->reveal())->isRefreshed());
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

        $byCookie = $this->sessions(self::BROWSER)->signIn('password', self::credentials())->session;
        $byBearer = $this->sessions(self::BROWSER)->signIn('password', self::credentials())->session;

        self::assertNotNull($byCookie);
        self::assertNotNull($byBearer);

        $value = self::cookieValue($byCookie->tokens);

        app()->instance('request', Request::create('/auth/logout', 'POST', [], [self::COOKIES[self::BROWSER][0] => $value], [], [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
            'HTTP_ORIGIN'     => 'http://localhost',
        ]));

        Auth::forgetGuards();

        $crossSite = Auth::sessions(self::BROWSER)->signOutFromRequest();

        app()->instance('request', Request::create('/auth/logout', 'POST', server: [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
            'HTTP_ORIGIN'     => 'https://elsewhere.example',
        ]));

        Auth::forgetGuards();

        $fromElsewhere = Auth::sessions(self::BROWSER)->signOutFromRequest();
        $conflict      = $this->request(self::BROWSER, ['refresh_token' => $value], [self::COOKIES[self::BROWSER][0] => $value])->signOutFromRequest();

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

        $bearer  = Auth::sessions(self::BROWSER)->signOutFromRequest();
        $signed  = $this->fromCookie(self::BROWSER, $value)->signOutFromRequest();
        $nothing = $this->request(self::BROWSER)->signOutFromRequest();

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

        $body    = $this->sessions(self::BODY)->signIn('password', self::credentials())->session;
        $browser = $this->sessions(self::BROWSER)->signIn('password', self::credentials())->session;

        self::assertNotNull($body);
        self::assertNotNull($browser);

        $other = (string) $body->tokens->refreshToken?->reveal();

        self::assertNull($this->request(self::BROWSER, cookies: ['__Secure-api_refresh_token' => $other])->refreshFromRequest());
        self::assertSame(FailureReason::TOKEN_INVALID, $this->fromCookie(self::BROWSER, $other)->refreshFromRequest()?->reason);

        $crossed = Auth::jwt(self::BROWSER)->issueRefreshToken($body->record, 'rotation-of-the-api-session', $body->principal)->reveal();
        $before  = Session::query()->whereKey($body->record->getKey())->sole()->getAttributes();

        self::assertSame(FailureReason::SESSION_GUARD_MISMATCH, $this->fromCookie(self::BROWSER, $crossed)->refreshFromRequest()?->reason);
        self::assertSame($before, Session::query()->whereKey($body->record->getKey())->sole()->getAttributes());

        self::assertSame(FailureReason::REFRESH_TRANSPORT_MISMATCH, $this->request(self::BODY, cookies: ['__Secure-api_refresh_token' => $other])->refreshFromRequest()?->reason);
        self::assertSame(
            FailureReason::REFRESH_TRANSPORT_MISMATCH,
            $this->request(self::BROWSER, ['refresh_token' => self::cookieValue($browser->tokens)])->refreshFromRequest()?->reason,
        );
    }

    /**
     * Configure the guards: `api` keeps the body transport, `admin` travels by
     * cookie under `/auth`, and `members` by cookie on the root path.
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
