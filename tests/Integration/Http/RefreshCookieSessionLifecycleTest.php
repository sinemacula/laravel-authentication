<?php

declare(strict_types = 1);

namespace Tests\Integration\Http;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SwitchesSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * End-to-end tests for a browser session whose refresh token lives in the
 * HttpOnly cookie.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenTransport::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(SessionRevocations::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(SessionSignOut::class)]
#[CoversTrait(EndsSessions::class)]
#[CoversTrait(SwitchesSessions::class)]
final class RefreshCookieSessionLifecycleTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`, reading the refresh token from the cookie only. */
    private const string GUARD = 'members';

    /** @var string The refresh cookie's name. */
    private const string COOKIE = '__Secure-members_refresh_token';

    /** @var array<string, string> The headers a same-origin browser script sends. */
    private const array SAME_ORIGIN = ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest'];

    /**
     * Freeze the clocks, create the tables and add the browser routes.
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

        Route::post('/auth/sign-in', static fn (Request $request): JsonResponse => self::signInRoute($request));
        Route::post('/auth/refresh', static fn (): JsonResponse => self::refreshRoute());
        Route::post('/auth/switch', static fn (Request $request): JsonResponse => self::switchRoute($request));
        Route::post('/auth/logout', static fn (): Response => self::signOutServed(Auth::sessions(self::GUARD), self::GUARD)->attachTo(new Response(status: 204)));
        Route::post('/logout', static fn (): JsonResponse => self::logoutRoute());
        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);
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
     * A switch proven by the cookie moves the session and sets the rotated
     * cookie.
     *
     * @return void
     */
    public function testASwitchReadFromTheCookieIsAnsweredWithTheCookie(): void
    {
        [, $second] = $this->seedMemberships();

        $signIn = $this->browser('POST', '/auth/sign-in')->assertOk();
        $cookie = self::refreshCookie($signIn);
        $access = $signIn->json('access_token');

        self::assertIsString($access);

        $switch  = $this->browser('POST', '/auth/switch', $cookie, ['membership' => $second->getKey()])->assertOk();
        $rotated = self::refreshCookie($switch);

        self::assertNotSame($cookie->getValue(), $rotated->getValue());
        self::assertSame('/auth', $rotated->getPath());
        self::assertSame($second->id, $switch->json('principal'));

        $switched = $switch->json('access_token');

        self::assertIsString($switched);

        $this->browser('GET', '/me', bearer: $access)->assertUnauthorized();
        $this->browser('GET', '/me', bearer: $switched)->assertOk()->assertJson(['principal' => $second->id]);
        $this->browser('POST', '/auth/refresh', $rotated)->assertOk()->assertJson(['source' => 'cookie']);
    }

    /**
     * A switch sent from another site is refused before the session is touched.
     *
     * @return void
     */
    public function testASwitchFromAnotherSiteIsRefusedBeforeTheSessionIsTouched(): void
    {
        [$first, $second] = $this->seedMemberships();

        $cookie = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk());
        $before = DB::table('authentication_sessions')->first(['principal_id', 'refresh_key']);

        $this->browser('POST', '/auth/switch', $cookie, ['membership' => $second->getKey()], ['Origin' => 'https://evil.example', 'X-Requested-With' => 'XMLHttpRequest'])
            ->assertUnauthorized()
            ->assertJson(['reason' => 'cross_site_request']);

        $this->browser('POST', '/auth/switch', $cookie, ['membership' => $second->getKey()], ['Origin' => 'http://localhost'])
            ->assertUnauthorized()
            ->assertJson(['reason' => 'cross_site_request']);

        self::assertEquals($before, DB::table('authentication_sessions')->first(['principal_id', 'refresh_key']));
        self::assertSame((string) $first->id, DB::table('authentication_sessions')->value('principal_id'));

        $this->browser('POST', '/auth/refresh', $cookie)->assertOk();
    }

    /**
     * A rate-limited refresh is answered with a 429 carrying `Retry-After`.
     *
     * @return void
     */
    public function testARateLimitedRefreshIsAnsweredWithRetryAfter(): void
    {
        $this->seedMemberships();

        $cookie = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk());
        $before = DB::table('authentication_sessions')->value('refresh_key');

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturn(42);

        app()->instance(AttemptLimiter::class, $limiter);

        $this->browser('POST', '/auth/refresh', $cookie)
            ->assertTooManyRequests()
            ->assertHeader('Retry-After', '42')
            ->assertCookieMissing(self::COOKIE);

        self::assertSame($before, DB::table('authentication_sessions')->value('refresh_key'));
    }

    /**
     * A rate-limited switch is answered with a 429 carrying `Retry-After`.
     *
     * @return void
     */
    public function testARateLimitedSwitchIsAnsweredWithRetryAfter(): void
    {
        [, $second] = $this->seedMemberships();

        $cookie = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk());
        $before = DB::table('authentication_sessions')->first(['principal_id', 'refresh_key']);

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturn(42);

        app()->instance(AttemptLimiter::class, $limiter);

        $this->browser('POST', '/auth/switch', $cookie, ['membership' => $second->getKey()])
            ->assertTooManyRequests()
            ->assertHeader('Retry-After', '42');

        self::assertEquals($before, DB::table('authentication_sessions')->first(['principal_id', 'refresh_key']));
    }

    /**
     * Signing in while holding the refresh cookie supersedes the old session.
     *
     * @return void
     */
    public function testASignInFromABrowserHoldingTheCookieReplacesItsSession(): void
    {
        $this->seedMemberships();

        $signIn = $this->browser('POST', '/auth/sign-in')->assertOk();
        $first  = self::refreshCookie($signIn);
        $access = $signIn->json('access_token');
        $record = DB::table('authentication_sessions')->value('id');

        self::assertIsString($access);

        $this->browser('GET', '/me', bearer: $access)->assertOk();

        $second = self::refreshCookie($this->browser('POST', '/auth/sign-in', $first)->assertOk());

        self::assertSame(2, DB::table('authentication_sessions')->count());
        self::assertSame('superseded', DB::table('authentication_sessions')->where('id', $record)->value('revoked_reason'));
        self::assertSame(1, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertNotSame($first->getValue(), $second->getValue());

        $this->browser('GET', '/me', bearer: $access)->assertUnauthorized();
        $this->browser('POST', '/auth/refresh', $first)->assertUnauthorized()->assertJson(['reason' => 'session_revoked']);
        $this->browser('POST', '/auth/refresh', $second)->assertOk();
    }

    /**
     * A sign-in from another site or without the custom header sets no cookie.
     *
     * @return void
     */
    public function testASignInFromAnotherSiteSetsNoCookie(): void
    {
        $this->seedMemberships();

        $refused = [
            ['Origin' => 'https://evil.example', 'X-Requested-With' => 'XMLHttpRequest'],
            ['Origin' => 'http://localhost'],
            ['Origin' => 'https://evil.example'],
            [],
        ];

        foreach ($refused as $headers) {

            $response = $this->browser('POST', '/auth/sign-in', headers: $headers);

            $response->assertForbidden()->assertJson(['reason' => 'cross_site_request']);

            self::assertSame([], $response->headers->getCookies());
        }

        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame(0, DB::table('authentication_proofs')->count());
    }

    /**
     * Logging out revokes the session and clears the cookie.
     *
     * @return void
     */
    public function testLoggingOutRevokesTheSessionAndClearsTheCookie(): void
    {
        $this->seedMemberships();

        $signIn = $this->browser('POST', '/auth/sign-in')->assertOk();
        $cookie = self::refreshCookie($signIn);
        $access = $signIn->json('access_token');

        self::assertIsString($access);

        $cleared = self::refreshCookie($this->browser('POST', '/logout', bearer: $access)->assertOk());

        self::assertTrue($cleared->isCleared());
        self::assertSame('/auth', $cleared->getPath());
        self::assertSame('signed_out', DB::table('authentication_sessions')->value('revoked_reason'));

        $this->browser('POST', '/auth/refresh', $cookie)->assertUnauthorized()->assertJson(['reason' => 'session_revoked']);
        $this->browser('GET', '/me', bearer: $access)->assertUnauthorized();
    }

    /**
     * A browser whose access token expired signs out with the cookie alone.
     *
     * @return void
     */
    public function testSigningOutAfterTheAccessTokenExpiredRevokesByTheCookie(): void
    {
        $this->seedMemberships();

        $signIn = $this->browser('POST', '/auth/sign-in')->assertOk();
        $cookie = self::refreshCookie($signIn);
        $access = $signIn->json('access_token');

        self::assertIsString($access);

        $later = CarbonImmutable::now()->addMinutes(20);

        Carbon::setTestNow($later);
        CarbonImmutable::setTestNow($later);

        JWT::$timestamp = $later->getTimestamp();

        $cleared = self::refreshCookie($this->browser('POST', '/auth/logout', $cookie, bearer: $access)->assertNoContent());

        self::assertTrue($cleared->isCleared());
        self::assertSame('/auth', $cleared->getPath());
        self::assertSame('signed_out', DB::table('authentication_sessions')->value('revoked_reason'));

        $this->browser('POST', '/auth/refresh', $cookie)->assertUnauthorized()->assertJson(['reason' => 'session_revoked']);

        $again = self::refreshCookie($this->browser('POST', '/auth/logout', $cookie)->assertNoContent());

        self::assertTrue($again->isCleared());
        self::assertSame('/auth', $again->getPath());
    }

    /**
     * A sign-out posted from another site neither revokes nor clears anything.
     *
     * @return void
     */
    public function testASignOutFromAnotherSiteRevokesAndClearsNothing(): void
    {
        $this->seedMemberships();

        $cookie = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk());

        foreach ([$cookie, null] as $sent) {

            $response = $this->browser('POST', '/auth/logout', $sent, headers: ['Origin' => 'https://evil.example'])->assertNoContent();

            self::assertSame([], array_filter($response->headers->getCookies(), static fn (Cookie $set): bool => $set->getName() === self::COOKIE));
        }

        $outside = $this->browser('POST', '/logout', headers: ['Origin' => 'https://evil.example'])->assertUnauthorized();

        self::assertSame([], $outside->headers->getCookies());
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));

        $this->browser('POST', '/auth/refresh', $cookie)->assertOk();
    }

    /**
     * Configure the guards, the `members` guard's refresh token travelling by
     * cookie under `/auth`.
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

        $config->set('auth.guards.members.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);
    }

    /**
     * Sign the member in as its default membership and answer with the token
     * pair.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function signInRoute(Request $request): JsonResponse
    {
        $member    = ActivatableTenantMember::query()->where('email', 'member@example.test')->firstOrFail();
        $presented = Auth::refreshTransport(self::GUARD)->extract($request);
        $proven    = $presented instanceof PresentedRefreshToken ? $presented->token : null;
        $context   = SignInContext::fromRequest($request, principal: $member->resolveDefaultPrincipal(), refreshToken: $proven);
        $result    = Auth::sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'), $context);

        if ($result->reason === FailureReason::CROSS_SITE_REQUEST) {
            return new JsonResponse(['reason' => $result->reason->value], 403);
        }

        $tokens = $result->session?->tokens;

        assert($tokens?->refreshCookie !== null);

        return $tokens->refreshCookie->attachTo(SecretResponse::json(['access_token' => $tokens->accessToken]));
    }

    /**
     * Refresh with the cookie and answer with the rotated one or the refusal.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private static function refreshRoute(): JsonResponse
    {
        $result = Auth::sessions(self::GUARD)->refresh(self::servedToken(self::GUARD), self::requestClient());

        if ($result?->reason === FailureReason::RATE_LIMITED) {
            throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
        }

        if ($result?->session === null) {
            return new JsonResponse(['reason' => $result?->reason?->value], 401);
        }

        $tokens = $result->session->tokens;

        assert($tokens->refreshCookie !== null);

        return $tokens->refreshCookie->attachTo(SecretResponse::json(['access_token' => $tokens->accessToken, 'source' => $result->source?->value]));
    }

    /**
     * Switch the session to the membership named and answer with the rotated
     * cookie or the refusal.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private static function switchRoute(Request $request): JsonResponse
    {
        $target = ActivatableTenantMembership::query()->findOrFail($request->integer('membership'));
        $result = Auth::sessions(self::GUARD)->switchTo(self::servedToken(self::GUARD), SwitchTarget::principal($target), self::requestClient());

        if ($result?->reason === FailureReason::RATE_LIMITED) {
            throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
        }

        if ($result?->session === null) {
            return new JsonResponse(['reason' => $result?->reason?->value], 401);
        }

        $tokens   = $result->session->tokens;
        $response = SecretResponse::json(['access_token' => $tokens->accessToken, 'principal' => $result->session->principal->getPrincipalIdentifier()]);

        assert($result->source === RefreshTokenSource::COOKIE && $tokens->refreshCookie !== null);

        return $tokens->refreshCookie->attachTo($response);
    }

    /**
     * Sign the session out by its access token and clear the cookie only if
     * that succeeded.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function logoutRoute(): JsonResponse
    {
        if (!Auth::sessions(self::GUARD)->signOut()) {
            return new JsonResponse(['signed_out' => false], 401);
        }

        return (new JsonResponse(['signed_out' => true]))->withCookie(Auth::refreshTransport(self::GUARD)->forgetCookie());
    }

    /**
     * Persist a member with a membership in an active tenant (its default
     * principal) and a second one in another active tenant.
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMembership, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership}
     */
    private function seedMemberships(): array
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        return [$first, $second];
    }

    /**
     * Send a request as a same-origin browser script does, with the cookie the
     * browser holds, if any, sent back as it was set.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $cookie
     * @param  array<string, mixed>  $input
     * @param  array<string, string>  $headers
     * @param  ?string  $bearer
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function browser(string $method, string $uri, ?Cookie $cookie = null, array $input = [], array $headers = self::SAME_ORIGIN, ?string $bearer = null): TestResponse
    {
        Auth::forgetGuards();

        $cookies = $cookie === null ? [] : [$cookie->getName() => $cookie->getValue()];
        $headers = $bearer === null ? $headers : [...$headers, 'Authorization' => 'Bearer ' . $bearer, 'Accept' => 'application/json'];

        return $this->call($method, $uri, $input, $cookies, [], $this->transformHeadersToServerVars($headers));
    }

    /**
     * The refresh cookie the response sets.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    private static function refreshCookie(TestResponse $response): Cookie
    {
        $cookies = array_values(array_filter($response->headers->getCookies(), static fn (Cookie $cookie): bool => $cookie->getName() === self::COOKIE));

        self::assertCount(1, $cookies);

        return $cookies[0];
    }
}
