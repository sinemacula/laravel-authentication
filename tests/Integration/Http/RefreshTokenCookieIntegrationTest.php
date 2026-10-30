<?php

declare(strict_types = 1);

namespace Tests\Integration\Http;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use Symfony\Component\HttpFoundation\Cookie;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * End-to-end tests for a browser that keeps its refresh token in the HttpOnly
 * cookie: the API sets it on sign-in and on each refresh, the browser sends it
 * back on its own, a route outside the cookie's path clears it, and nothing is
 * stored on the server. Run with the cookie left out of Laravel's cookie
 * encryption and with the routes encrypting it, both of which round-trip.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenTransport::class)]
#[CoversClass(JwtGuard::class)]
final class RefreshTokenCookieIntegrationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The refresh cookie's name. */
    private const string COOKIE = '__Secure-refresh_token';

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
                Route::post('/logout', static fn (): JsonResponse => (new JsonResponse(['signed_out' => true]))->withCookie(Auth::refreshTransport($guard)->forgetCookie()));
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
     * logging out from a route outside the cookie's path clears it.
     *
     * @param  string  $guard
     * @param  bool  $excluded
     * @return void
     */
    #[DataProvider('provideSetups')]
    public function testABrowserKeepsItsSessionInTheCookie(string $guard, bool $excluded): void
    {
        if ($excluded) {
            EncryptCookies::except(self::COOKIE);
        }

        $this->seedIdentity();

        $prefix = $guard === 'admin' ? '/admin' : '';
        $signIn = $this->browser('POST', $prefix . '/auth/sign-in')->assertOk();
        $cookie = self::refreshCookie($signIn);
        $issued = $signIn->json('refresh_token');

        self::assertIsString($issued);
        self::assertSame($excluded, $cookie->getValue() === $issued);

        $first  = $this->browser('POST', $prefix . '/auth/refresh', $cookie)->assertOk()->assertJson(['source' => 'cookie']);
        $second = $this->browser('POST', $prefix . '/auth/refresh', self::refreshCookie($first))->assertOk()->assertJson(['source' => 'cookie']);

        self::assertNotSame($cookie->getValue(), self::refreshCookie($second)->getValue());

        $cleared = self::refreshCookie($this->browser('POST', $prefix . '/logout')->assertOk());

        self::assertTrue($cleared->isCleared());
        self::assertSame($prefix . '/auth', $cleared->getPath());
    }

    /**
     * The cookie is scoped and protected as configured, and expires when the
     * refresh token it carries does: the end of the device's session.
     *
     * @return void
     */
    public function testTheCookieExpiresWithTheRefreshToken(): void
    {
        EncryptCookies::except(self::COOKIE);

        $this->seedIdentity();

        $response = $this->browser('POST', '/auth/sign-in')->assertOk();
        $cookie   = self::refreshCookie($response);
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

        $this->browser('POST', '/auth/refresh', Cookie::create(self::COOKIE, 'not-encrypted'))
            ->assertUnauthorized()
            ->assertJson(['reason' => 'token_invalid']);
    }

    /**
     * Configure the guards to read only the cookie: `api` under `/auth`,
     * `admin` under `/admin/auth`.
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

        $config->set('auth.guards.api.refresh_token', ['sources' => ['cookie'], 'cookie' => ['path' => '/auth']]);
        $config->set('auth.guards.admin.refresh_token', ['sources' => ['cookie'], 'cookie' => ['path' => '/admin/auth']]);
    }

    /**
     * Sign the seeded identity in on the guard and answer with the access token
     * in the body and the refresh token in the cookie (and, for the test's own
     * checks, in the body).
     *
     * @param  string  $guard
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function signInRoute(string $guard): JsonResponse
    {
        $session = Auth::sessions($guard)->signIn('password', self::credentials())->session;

        assert($session !== null);

        return (new JsonResponse(['access_token' => $session->tokens->accessToken, 'refresh_token' => $session->tokens->refreshToken]))
            ->withCookie(Auth::refreshTransport($guard)->cookie($session->tokens->refreshToken, $session->device));
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
        $jwt = Auth::manager()->guard($guard);

        assert($jwt instanceof JwtGuard);

        $result = $jwt->refreshFromRequest();

        if (!$result instanceof RefreshResult) {
            return new JsonResponse(['reason' => $result?->value], 401);
        }

        $device = $jwt->device();

        assert($device !== null && $result->source === RefreshTokenSource::COOKIE);

        return (new JsonResponse(['access_token' => $result->accessToken, 'source' => $result->source->value]))
            ->withCookie(Auth::refreshTransport($guard)->cookie($result->refreshToken, $device));
    }

    /**
     * Send a request as a same-origin browser script does, with the cookie the
     * browser holds, if any, sent back as it was set.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $cookie
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function browser(string $method, string $uri, ?Cookie $cookie = null): TestResponse
    {
        Auth::forgetGuards();

        $cookies = $cookie === null ? [] : [$cookie->getName() => $cookie->getValue()];

        return $this->call($method, $uri, [], $cookies, [], $this->transformHeadersToServerVars(self::SAME_ORIGIN));
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
