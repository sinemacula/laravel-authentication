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
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Symfony\Component\HttpFoundation\Cookie;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * End-to-end tests for a browser whose refresh token lives in the HttpOnly
 * cookie, through the rest of its session: a switch of principal proven by the
 * cookie, held to the cookie's cross-site checks and answered with the rotated
 * cookie, and a sign-out from a route outside the cookie's path that revokes
 * the device and clears the cookie, as the documented routes do.
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
#[CoversTrait(EndsSessions::class)]
final class RefreshCookieSessionLifecycleTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`, reading the refresh token from the cookie only. */
    private const string GUARD = 'members';

    /** @var string The refresh cookie's name. */
    private const string COOKIE = '__Secure-refresh_token';

    /** @var array<string, string> The headers a same-origin browser script sends. */
    private const array SAME_ORIGIN = ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest'];

    /**
     * Freeze the clocks, create the tables, and add the browser routes:
     * sign-in, refresh and switch under the cookie's `/auth` path, and logout
     * and a protected route outside it.
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
     * A switch proven by the cookie moves the session to the other membership
     * and sets the rotated cookie: the old membership's access token stops at
     * once, the new one acts as the target, and the new cookie keeps
     * refreshing.
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
     * A switch that sends the cookie from another site is refused by the
     * cookie's checks before the session service is reached: the device keeps
     * its principal and its credential, and the cookie still refreshes.
     *
     * @return void
     */
    public function testASwitchFromAnotherSiteIsRefusedBeforeTheSessionIsTouched(): void
    {
        [$first, $second] = $this->seedMemberships();

        $cookie = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk());
        $before = DB::table('devices')->first(['principal_id', 'refresh_key']);

        $this->browser('POST', '/auth/switch', $cookie, ['membership' => $second->getKey()], ['Origin' => 'https://evil.example', 'X-Requested-With' => 'XMLHttpRequest'])
            ->assertUnauthorized()
            ->assertJson(['reason' => 'cross_site_request']);

        $this->browser('POST', '/auth/switch', $cookie, ['membership' => $second->getKey()], ['Origin' => 'http://localhost'])
            ->assertUnauthorized()
            ->assertJson(['reason' => 'cross_site_request']);

        self::assertEquals($before, DB::table('devices')->first(['principal_id', 'refresh_key']));
        self::assertSame((string) $first->id, DB::table('devices')->value('principal_id'));

        $this->browser('POST', '/auth/refresh', $cookie)->assertOk();
    }

    /**
     * A refresh the limits refuse is answered by the route with a 429 carrying
     * `Retry-After`, so the client waits; the cookie is left as it was, and the
     * session as well.
     *
     * @return void
     */
    public function testARateLimitedRefreshIsAnsweredWithRetryAfter(): void
    {
        $this->seedMemberships();

        $cookie = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk());
        $before = DB::table('devices')->value('refresh_key');

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturn(42);

        app()->instance(AttemptLimiter::class, $limiter);

        $this->browser('POST', '/auth/refresh', $cookie)
            ->assertTooManyRequests()
            ->assertHeader('Retry-After', '42')
            ->assertCookieMissing(self::COOKIE);

        self::assertSame($before, DB::table('devices')->value('refresh_key'));
    }

    /**
     * A switch the refresh limits refuse is answered as a refused refresh is,
     * with a 429 carrying `Retry-After`, so the client waits; the session is
     * left as it was.
     *
     * @return void
     */
    public function testARateLimitedSwitchIsAnsweredWithRetryAfter(): void
    {
        [, $second] = $this->seedMemberships();

        $cookie = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk());
        $before = DB::table('devices')->first(['principal_id', 'refresh_key']);

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturn(42);

        app()->instance(AttemptLimiter::class, $limiter);

        $this->browser('POST', '/auth/switch', $cookie, ['membership' => $second->getKey()])
            ->assertTooManyRequests()
            ->assertHeader('Retry-After', '42');

        self::assertEquals($before, DB::table('devices')->first(['principal_id', 'refresh_key']));
    }

    /**
     * A browser that signs in again while it holds the refresh cookie proves
     * its device through it, so the sign-in continues that device rather than
     * starting another, and the new cookie refreshes it.
     *
     * @return void
     */
    public function testASignInFromABrowserHoldingTheCookieContinuesItsDevice(): void
    {
        $this->seedMemberships();

        $first  = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk());
        $device = DB::table('devices')->value('id');
        $second = self::refreshCookie($this->browser('POST', '/auth/sign-in', $first)->assertOk());

        self::assertSame(1, DB::table('devices')->count());
        self::assertSame($device, DB::table('devices')->value('id'));

        self::assertNotSame($first->getValue(), $second->getValue());

        $this->browser('POST', '/auth/refresh', $second)->assertOk();
    }

    /**
     * A sign-in posted from another site, or without the custom header, is
     * refused before any session starts and sets no cookie, so a cross-site
     * form cannot sign the browser into another account.
     *
     * @return void
     */
    public function testASignInFromAnotherSiteSetsNoCookie(): void
    {
        $this->seedMemberships();

        foreach ([['Origin' => 'https://evil.example', 'X-Requested-With' => 'XMLHttpRequest'], ['Origin' => 'http://localhost'], []] as $headers) {

            $response = $this->browser('POST', '/auth/sign-in', headers: $headers)->assertForbidden();

            self::assertSame([], $response->headers->getCookies());
        }

        self::assertSame(0, DB::table('devices')->count());
    }

    /**
     * Logging out from a route outside the cookie's path revokes the session's
     * device and clears the cookie: the cookie it held no longer refreshes and
     * the access token no longer authenticates.
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
        self::assertSame('signed_out', DB::table('devices')->value('revoked_reason'));

        $this->browser('POST', '/auth/refresh', $cookie)->assertUnauthorized()->assertJson(['reason' => 'device_revoked']);
        $this->browser('GET', '/me', bearer: $access)->assertUnauthorized();
    }

    /**
     * Configure the guards, the `members` guard reading the refresh token only
     * from the cookie under `/auth`.
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

        $config->set('auth.guards.members.refresh_token', ['sources' => ['cookie'], 'cookie' => ['path' => '/auth']]);
    }

    /**
     * Sign the member in as its default membership and answer with the access
     * token in the body and the refresh token in the cookie, for a request from
     * the API's own site only: a cross-site form must not sign the browser in.
     * A browser that holds the cookie proves its device with it.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function signInRoute(Request $request): JsonResponse
    {
        $transport = Auth::refreshTransport(self::GUARD);

        if (!$transport->isSameSiteRequest($request)) {
            return new JsonResponse(['reason' => 'cross_site_request'], 403);
        }

        $presented = $transport->read($request);
        $context   = SignInContext::fromRequest($request, refreshToken: $presented instanceof PresentedRefreshToken ? $presented->token : null);
        $session   = Auth::sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'), $context)->session;

        assert($session !== null);

        return (new JsonResponse(['access_token' => $session->tokens->accessToken]))
            ->withCookie($transport->cookie($session->tokens->refreshToken, $session->device));
    }

    /**
     * Refresh with the cookie and answer with the rotated one, a rate-limited
     * refresh with a 429 carrying `Retry-After`, or another refusal with its
     * reason.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private static function refreshRoute(): JsonResponse
    {
        $result = Auth::sessions(self::GUARD)->refreshFromRequest();

        if ($result?->reason === FailureReason::RATE_LIMITED) {
            throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
        }

        if ($result?->session === null) {
            return new JsonResponse(['reason' => $result?->reason?->value], 401);
        }

        $tokens = $result->session->tokens;

        return (new JsonResponse(['access_token' => $tokens->accessToken, 'source' => $result->source?->value]))
            ->withCookie(Auth::refreshTransport(self::GUARD)->cookie($tokens->refreshToken, $result->session->device));
    }

    /**
     * Switch the session proven by the refresh token the guard's transport
     * reads from the request to the membership named, answering a switch read
     * from the cookie with the rotated cookie, a rate-limited one with a 429
     * carrying `Retry-After`, or another refusal with its reason.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private static function switchRoute(Request $request): JsonResponse
    {
        $target = ActivatableTenantMembership::query()->findOrFail($request->integer('membership'));
        $result = Auth::sessions(self::GUARD)->switchPrincipalFromRequest($target);

        if ($result?->reason === FailureReason::RATE_LIMITED) {
            throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
        }

        if ($result?->session === null) {
            return new JsonResponse(['reason' => $result?->reason?->value], 401);
        }

        $response = new JsonResponse(['access_token' => $result->session->tokens->accessToken, 'principal' => $result->session->principal->getPrincipalIdentifier()]);

        return $result->source === RefreshTokenSource::COOKIE
            ? $response->withCookie(Auth::refreshTransport(self::GUARD)->cookie($result->session->tokens->refreshToken, $result->session->device))
            : $response;
    }

    /**
     * Sign the request's session out and clear the cookie, from a route outside
     * the cookie's path.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function logoutRoute(): JsonResponse
    {
        Auth::guard(self::GUARD)->logout();

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
