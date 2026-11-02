<?php

declare(strict_types = 1);

namespace Tests\Integration\Http;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\RefreshCookie;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use Symfony\Component\HttpFoundation\Cookie;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * End-to-end tests for a browser application that keeps its refresh token in
 * the HttpOnly cookie: the API sets it on sign-in and on each refresh, the
 * browser sends it back on its own, a route outside the cookie's path clears
 * it, and nothing is stored on the server. The application never sees the plain
 * refresh token: its results carry the cookie. Run with the cookie left out of
 * Laravel's cookie encryption and with the routes encrypting it, both of which
 * round-trip, and with two browser applications on one host, whose cookies,
 * named after each application, never overwrite each other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenTransport::class)]
#[CoversClass(RefreshCookie::class)]
#[CoversClass(JwtGuard::class)]
final class RefreshTokenCookieIntegrationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var array<string, string> The refresh cookie's name each application derives from its guard, on a path below the root. */
    private const array COOKIES = ['api' => '__Secure-api_refresh_token', 'admin' => '__Secure-admin_refresh_token'];

    /** @var array<string, string> The headers a same-origin browser script sends with a refresh. */
    private const array SAME_ORIGIN = ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest'];

    /**
     * Freeze the clocks, create the tables, and add the browser routes of the
     * `api` guard, its cookie scoped to `/auth`, and of the `admin` guard, its
     * cookie scoped to `/admin/auth`, each with a logout route outside it.
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

        foreach (['api' => '', 'admin' => '/admin'] as $guard => $prefix) {
            Route::middleware(EncryptCookies::class)->prefix($prefix)->group(static function () use ($guard): void {
                Route::post('/auth/sign-in', static fn (): JsonResponse => self::signInRoute($guard));
                Route::post('/auth/refresh', static fn (): JsonResponse => self::refreshRoute($guard));
                Route::post('/logout', static fn (Request $request): JsonResponse => self::logoutRoute($guard, $request));
            });
        }
    }

    /**
     * Release the clocks, forget the cookie encryption exceptions and drop the
     * tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        EncryptCookies::flushState();

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Rows of `[the guard, whether the cookie is left out of encryption]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideSetups(): iterable
    {
        yield 'left out of encryption' => ['api', true];
        yield 'encrypted by the routes' => ['api', false];
        yield 'another guard and path' => ['admin', true];
    }

    /**
     * Sign-in sets the cookie, each refresh reads it and sets the rotated one,
     * and the cookie the API set is all the browser needs to keep refreshing;
     * logging out from a route outside the cookie's path clears it, for a
     * request from the API's own site only.
     *
     * @param  string  $guard
     * @param  bool  $excluded
     * @return void
     */
    #[DataProvider('provideSetups')]
    public function testABrowserKeepsItsSessionInTheCookie(string $guard, bool $excluded): void
    {
        if ($excluded) {
            EncryptCookies::except(self::COOKIES[$guard]);
        }

        $this->seedIdentity();

        $prefix = $guard === 'admin' ? '/admin' : '';
        $signIn = $this->browser('POST', $prefix . '/auth/sign-in')->assertOk();
        $cookie = self::refreshCookie($signIn, $guard);
        $issued = $signIn->json('cookie_value');

        self::assertIsString($issued);
        self::assertSame($excluded, $cookie->getValue() === $issued);
        self::assertNull($signIn->json('refresh_token'));
        self::assertTrue($signIn->headers->hasCacheControlDirective('no-store'));

        $first  = $this->browser('POST', $prefix . '/auth/refresh', $cookie)->assertOk()->assertJson(['source' => 'cookie', 'refresh_token' => null]);
        $second = $this->browser('POST', $prefix . '/auth/refresh', self::refreshCookie($first, $guard))->assertOk()->assertJson(['source' => 'cookie']);

        self::assertNotSame($cookie->getValue(), self::refreshCookie($second, $guard)->getValue());

        $crossSite = $this->call('POST', $prefix . '/logout', server: $this->transformHeadersToServerVars(['Origin' => 'https://evil.example']));

        self::assertSame([], $crossSite->assertForbidden()->headers->getCookies());

        $cleared = self::refreshCookie($this->browser('POST', $prefix . '/logout')->assertOk(), $guard);

        self::assertTrue($cleared->isCleared());
        self::assertSame($prefix . '/auth', $cleared->getPath());
    }

    /**
     * The cookie is scoped and protected as configured, and expires when the
     * refresh token it carries does: the end of the session.
     *
     * @return void
     */
    public function testTheCookieExpiresWithTheRefreshToken(): void
    {
        EncryptCookies::except(self::COOKIES['api']);

        $this->seedIdentity();

        $response = $this->browser('POST', '/auth/sign-in')->assertOk();
        $cookie   = self::refreshCookie($response, 'api');
        $claims   = Auth::jwt('api')->parse($cookie->getValue() ?? '', TokenType::REFRESH);

        self::assertIsArray($claims);
        self::assertSame($claims[Claims::EXPIRES_AT->value], $cookie->getExpiresTime());
        self::assertSame('/auth', $cookie->getPath());
        self::assertNull($cookie->getDomain());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame(Cookie::SAMESITE_STRICT, $cookie->getSameSite());
    }

    /**
     * A cookie the routes cannot decrypt is an invalid token, not a missing
     * one, so the client is told to sign in again.
     *
     * @return void
     */
    public function testACookieThatCannotBeDecryptedIsAnInvalidToken(): void
    {
        $this->seedIdentity();
        $this->browser('POST', '/auth/sign-in')->assertOk();

        $this->browser('POST', '/auth/refresh', Cookie::create(self::COOKIES['api'], 'not-encrypted'))
            ->assertUnauthorized()
            ->assertJson(['reason' => 'token_invalid']);
    }

    /**
     * Two browser applications on one host, both on the root path, keep
     * separate cookies: each derives a `__Host-` name of its own, so a browser
     * that holds and sends both refreshes each application from its own, each
     * response sets only its own, and neither is read as the other's.
     *
     * @return void
     */
    public function testTwoBrowserApplicationsOnOneHostKeepSeparateCookies(): void
    {
        config()->set('auth.guards.api.refresh_token.cookie.path', '/');
        config()->set('auth.guards.admin.refresh_token.cookie.path', '/');

        EncryptCookies::except(['__Host-api_refresh_token', '__Host-admin_refresh_token']);

        $this->seedIdentity();

        $api   = self::refreshCookie($this->browser('POST', '/auth/sign-in')->assertOk(), 'api', '__Host-api_refresh_token');
        $admin = self::refreshCookie($this->browser('POST', '/admin/auth/sign-in')->assertOk(), 'admin', '__Host-admin_refresh_token');

        self::assertSame(['/', '/'], [$api->getPath(), $admin->getPath()]);

        $refreshedApi   = $this->browser('POST', '/auth/refresh', $api, $admin)->assertOk()->assertJson(['source' => 'cookie']);
        $refreshedAdmin = $this->browser('POST', '/admin/auth/refresh', $api, $admin)->assertOk()->assertJson(['source' => 'cookie']);

        self::assertSame(['__Host-api_refresh_token'], self::namesSet($refreshedApi));
        self::assertSame(['__Host-admin_refresh_token'], self::namesSet($refreshedAdmin));
        self::assertNotSame($api->getValue(), self::refreshCookie($refreshedApi, 'api', '__Host-api_refresh_token')->getValue());
    }

    /**
     * Configure both guards to travel by cookie: `api` under `/auth`, `admin`
     * under `/admin/auth`.
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

        $config->set('auth.guards.api.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);
        $config->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/admin/auth']]);
    }

    /**
     * Sign the seeded identity in on the guard and answer with the access token
     * in the body and the cookie its pair carries (and, for the test's own
     * checks, the cookie's value in the body).
     *
     * @param  string  $guard
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function signInRoute(string $guard): JsonResponse
    {
        $tokens = Auth::sessions($guard)->signIn('password', self::credentials())->session?->tokens;
        $cookie = $tokens?->refreshCookie;

        assert($tokens !== null && $cookie !== null);

        return $cookie->attachTo(SecretResponse::json([
            'access_token'  => $tokens->accessToken,
            'refresh_token' => $tokens->refreshToken,
            'cookie_value'  => $cookie->cookie()->getValue(),
        ]));
    }

    /**
     * Clear the guard's cookie from a route outside its path, for a request
     * from the API's own site only: a cross-site form must not sign the browser
     * out.
     *
     * @param  string  $guard
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function logoutRoute(string $guard, Request $request): JsonResponse
    {
        $transport = Auth::refreshTransport($guard);

        if (!$transport->isSameSiteRequest($request)) {
            return new JsonResponse(['reason' => 'cross_site_request'], 403);
        }

        return (new JsonResponse(['signed_out' => true]))->withCookie($transport->forgetCookie());
    }

    /**
     * Refresh with the token the request carries and answer a cookie refresh
     * with the rotated cookie, or with the refusal's reason.
     *
     * @param  string  $guard
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function refreshRoute(string $guard): JsonResponse
    {
        $result = Auth::sessions($guard)->refreshFromRequest();

        if ($result?->session === null) {
            return new JsonResponse(['reason' => $result?->reason?->value], 401);
        }

        assert($result->source === RefreshTokenSource::COOKIE);

        $tokens = $result->session->tokens;

        assert($tokens->refreshCookie !== null);

        return $tokens->refreshCookie->attachTo(SecretResponse::json([
            'access_token'  => $tokens->accessToken,
            'refresh_token' => $tokens->refreshToken,
            'source'        => $result->source->value,
        ]));
    }

    /**
     * Send a request as a same-origin browser script does, with the cookies the
     * browser holds, if any, sent back as they were set.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  \Symfony\Component\HttpFoundation\Cookie  ...$held
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function browser(string $method, string $uri, Cookie ...$held): TestResponse
    {
        Auth::forgetGuards();

        $cookies = [];

        foreach ($held as $cookie) {
            $cookies[$cookie->getName()] = $cookie->getValue();
        }

        return $this->call($method, $uri, [], $cookies, [], $this->transformHeadersToServerVars(self::SAME_ORIGIN));
    }

    /**
     * The refresh cookie of the guard the response sets, under the name given
     * or the one the guard derives below the root path.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  string  $guard
     * @param  ?string  $name
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    private static function refreshCookie(TestResponse $response, string $guard, ?string $name = null): Cookie
    {
        $name ??= self::COOKIES[$guard];
        $cookies = array_values(array_filter($response->headers->getCookies(), static fn (Cookie $cookie): bool => $cookie->getName() === $name));

        self::assertCount(1, $cookies);

        return $cookies[0];
    }

    /**
     * The names of the cookies the response sets.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return list<string>
     */
    private static function namesSet(TestResponse $response): array
    {
        return array_values(array_map(static fn (Cookie $cookie): string => $cookie->getName(), $response->headers->getCookies()));
    }
}
