<?php

declare(strict_types = 1);

namespace Tests\Integration\Http;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use Symfony\Component\HttpFoundation\Cookie;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * End-to-end tests for refreshing with the token a request carries, through a
 * route on a real database: each application reads its token by its own
 * transport, a token carried twice, carried by another transport or in a cookie
 * sent cross-site is refused without touching the session, a cookie
 * application's refresh answers with the cookie and never the token, and the
 * result says where the token came from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenTransport::class)]
#[CoversClass(JwtGuard::class)]
final class RefreshTokenTransportIntegrationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var array<string, string> The cookie name each application derives from its guard. */
    private const array COOKIES = ['api' => '__Secure-api_refresh_token', 'admin' => '__Secure-admin_refresh_token'];

    /**
     * Freeze the clocks, create the tables, and add a refresh route for each
     * guard that answers with the result's source, or the refusal's reason.
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

        Route::post('/auth/{guard}/refresh', static fn (string $guard): JsonResponse => self::refreshRoute($guard));
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
     * A token in the body is exchanged and the result says so; the rotated
     * token is then read from the header the same way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenIsReadFromTheBodyOrTheHeader(): void
    {
        $token = $this->signIn('api');

        $rotated = $this->postJson('/auth/api/refresh', ['refresh_token' => $token])->assertOk()->assertJson(['source' => 'body'])->json('refresh_token');

        self::assertIsString($rotated);

        $this->refresh('api', headers: ['X-Refresh-Token' => $rotated])->assertOk()->assertJson(['source' => 'header']);
    }

    /**
     * Rows of `[the guard, the request's query string, and the guard whose
     * cookie it carries]` that carry the token only where no application reads
     * it: the query string, or another application's cookie.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: ?string}>
     */
    public static function provideUnreadPlaces(): iterable
    {
        yield 'the query string' => ['api', true, null];
        yield 'the query string, for a cookie application' => ['admin', true, null];
        yield 'another application\'s cookie' => ['admin', false, 'api'];
    }

    /**
     * A token where no application reads one is not seen: nothing is attempted
     * and nothing is dispatched.
     *
     * @param  string  $guard
     * @param  bool  $query
     * @param  ?string  $cookieOf
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnreadPlaces')]
    public function testATokenWhereNoApplicationReadsIsNotSeen(string $guard, bool $query, ?string $cookieOf): void
    {
        $token = $this->signIn($guard);

        $this->recordEvents([AuthenticationFailed::class, Refreshed::class]);

        Auth::forgetGuards();

        $cookies = $cookieOf === null ? [] : [self::COOKIES[$cookieOf] => $token];
        $headers = $this->transformHeadersToServerVars(['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest']);

        $this->call('POST', '/auth/' . $guard . '/refresh' . ($query ? '?refresh_token=' . $token : ''), [], $cookies, [], $headers)->assertStatus(400);

        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Rows of `[the guard, the body, headers and cookie of a request the
     * transport refuses, the reason]`.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: array<string, string>, 3: bool, 4: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'the token in the body and a header' => ['api', true, ['X-Refresh-Token' => 'token'], false, FailureReason::REFRESH_TOKEN_CONFLICT];
        yield 'the cookie with the token in the body, to a cookie application' => [
            'admin',
            true,
            ['Origin' => 'http://localhost', 'X-Requested-With' => '1'],
            true,
            FailureReason::REFRESH_TOKEN_CONFLICT,
        ];
        yield 'the cookie with the token in the body, to a body application' => ['api', true, [], true, FailureReason::REFRESH_TOKEN_CONFLICT];
        yield 'the cookie, to a body application' => ['api', false, ['Origin' => 'http://localhost', 'X-Requested-With' => '1'], true, FailureReason::REFRESH_TRANSPORT_MISMATCH];
        yield 'the body, to a cookie application' => ['admin', true, [], false, FailureReason::REFRESH_TRANSPORT_MISMATCH];
        yield 'a header, to a cookie application' => ['admin', false, ['X-Refresh-Token' => 'token'], false, FailureReason::REFRESH_TRANSPORT_MISMATCH];
        yield 'the cookie without the custom header' => ['admin', false, ['Origin' => 'http://localhost'], true, FailureReason::CROSS_SITE_REQUEST];
        yield 'the cookie from another origin' => ['admin', false, ['Origin' => 'https://evil.test', 'X-Requested-With' => '1'], true, FailureReason::CROSS_SITE_REQUEST];
        yield 'the cookie without an origin' => ['admin', false, ['X-Requested-With' => 'XMLHttpRequest'], true, FailureReason::CROSS_SITE_REQUEST];
    }

    /**
     * A request the transport refuses is answered with its reason and reported
     * as a failed refresh, and leaves the session as it was: its token still
     * refreshes once sent the one allowed way.
     *
     * @param  string  $guard
     * @param  bool  $body
     * @param  array<string, string>  $headers
     * @param  bool  $cookie
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusals')]
    public function testARefusedRequestLeavesTheSessionAsItWas(string $guard, bool $body, array $headers, bool $cookie, FailureReason $reason): void
    {
        $token  = $this->signIn($guard);
        $before = Session::query()->sole()->getAttributes();

        $this->recordEvents([AuthenticationFailed::class]);

        $headers = array_map(static fn (string $value): string => $value === 'token' ? $token : $value, $headers);

        $this->refresh($guard, '', $body ? ['refresh_token' => $token] : [], $headers, $cookie ? $token : null)
            ->assertUnauthorized()
            ->assertJson(['reason' => $reason->value]);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::REFRESH, $failure->flow);
        self::assertSame($reason, $failure->reason);
        self::assertSame($guard, $failure->context->guard);
        self::assertSame($before, Session::query()->sole()->getAttributes());

        $allowed = $guard === 'admin'
            ? $this->refresh($guard, '', [], ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest'], $token)
            : $this->refresh($guard, '', ['refresh_token' => $token]);

        $allowed->assertOk();
    }

    /**
     * Rows of `[the cookie another host of the site planted]`, under the
     * refresh cookie's name or one PHP files under it.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePlantedCookies(): iterable
    {
        yield 'the same name' => ['__Secure-admin_refresh_token'];
        yield 'a name with a dot' => ['__Secure-admin_refresh.token'];
        yield 'a name with an unclosed bracket' => ['__Secure-admin_refresh[token'];
    }

    /**
     * A browser that sends a cookie another host of the site planted before its
     * own, as it does for a planted cookie with a longer path, is refused as a
     * conflict rather than refreshed with the cookie PHP kept, and its own
     * token still refreshes once the planted cookie is gone.
     *
     * @param  string  $planted
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('providePlantedCookies')]
    public function testACookiePlantedBesideTheBrowsersOwnIsAConflict(string $planted): void
    {
        $token  = $this->signIn('admin');
        $before = Session::query()->sole()->getAttributes();

        $this->recordEvents([AuthenticationFailed::class, Refreshed::class]);

        $headers = ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest', 'Cookie' => $planted . '=planted; ' . self::COOKIES['admin'] . '=' . $token];

        $this->refresh('admin', '', [], $headers, 'planted')
            ->assertUnauthorized()
            ->assertJson(['reason' => FailureReason::REFRESH_TOKEN_CONFLICT->value]);

        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($before, Session::query()->sole()->getAttributes());

        $this->refresh('admin', '', [], ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest', 'Cookie' => self::COOKIES['admin'] . '=' . $token], $token)
            ->assertOk()
            ->assertJson(['source' => 'cookie']);
    }

    /**
     * A package-wide `__Host-` cookie name binds only the application whose
     * transport is the cookie: it refreshes from it on the root path, and a
     * body application refreshes as before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHostCookieNameLeavesTheBodyApplicationsAlone(): void
    {
        config()->set([
            'authentication.refresh_token.cookie.name' => '__Host-refresh_token',
            'auth.guards.admin.refresh_token'          => ['transport' => 'cookie', 'cookie' => ['path' => '/']],
        ]);

        $api = $this->signIn('api');

        $this->refresh('api', '', ['refresh_token' => $api])->assertOk()->assertJson(['source' => 'body']);

        $admin = $this->sessions('admin')->signIn('password', self::credentials())->session?->tokens->refreshCookie;

        self::assertNotNull($admin);
        self::assertSame('__Host-refresh_token', $admin->name);

        Auth::forgetGuards();

        $headers = $this->transformHeadersToServerVars(['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest']);

        $this->call('POST', '/auth/admin/refresh', [], ['__Host-refresh_token' => $admin->cookie()->getValue()], [], $headers)
            ->assertOk()
            ->assertJson(['source' => 'cookie']);
    }

    /**
     * A cookie application on the root path derives a `__Host-` name of its
     * own, host-only, and refreshes from it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationOnTheRootPathDerivesAHostName(): void
    {
        config()->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/']]);

        $this->seedIdentity();

        $cookie = $this->sessions('admin')->signIn('password', self::credentials())->session?->tokens->refreshCookie?->cookie();

        self::assertNotNull($cookie);
        self::assertSame(['__Host-admin_refresh_token', '/', null], [$cookie->getName(), $cookie->getPath(), $cookie->getDomain()]);

        Auth::forgetGuards();

        $headers  = $this->transformHeadersToServerVars(['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest']);
        $response = $this->call('POST', '/auth/admin/refresh', [], [$cookie->getName() => $cookie->getValue()], [], $headers)->assertOk();

        self::assertSame(['__Host-admin_refresh_token'], array_map(static fn (Cookie $set): string => $set->getName(), $response->headers->getCookies()));
    }

    /**
     * A cookie refresh from the request's own origin with the custom header is
     * exchanged and the result says it came from the cookie; the response
     * carries the rotated token only in the application's cookie, never in the
     * body, and is not stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieRefreshFromTheOwnOriginIsExchanged(): void
    {
        $token = $this->signIn('admin');

        $response = $this->refresh('admin', '', [], ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest'], $token)
            ->assertOk()
            ->assertExactJson(['source' => 'cookie']);

        $set = $response->headers->getCookies();

        self::assertCount(1, $set);
        self::assertSame(self::COOKIES['admin'], $set[0]->getName());
        self::assertNotSame($token, $set[0]->getValue());
        self::assertSame('/auth', $set[0]->getPath());
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertStringNotContainsString((string) $set[0]->getValue(), (string) $response->baseResponse->getContent());
    }

    /**
     * A cookie refresh sent as a form from an allowed origin carries only
     * headers a browser sends on its own, so it is refused as cross-site; and a
     * guard told to take `Content-Type` for its custom header, or
     * `Content_Type`, which Symfony reads as the same header, fails closed
     * before the token is read, leaving the session as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFormRequestCannotStandInForTheCustomHeader(): void
    {
        $token  = $this->signIn('admin');
        $before = Session::query()->sole()->getAttributes();
        $form   = ['Origin' => 'http://localhost', 'Content-Type' => 'application/x-www-form-urlencoded'];

        $this->refresh('admin', '', ['remember' => '1'], $form, $token)
            ->assertUnauthorized()
            ->assertJson(['reason' => FailureReason::CROSS_SITE_REQUEST->value]);

        foreach (['Content-Type', 'Content_Type'] as $header) {
            config()->set('auth.guards.admin.refresh_token.cookie.csrf_header', $header);

            $refused = $this->refresh('admin', '', ['remember' => '1'], $form, $token)->assertInternalServerError();

            self::assertInstanceOf(\InvalidArgumentException::class, $refused->exception);
            self::assertStringContainsString('`refresh_token.cookie.csrf_header` must be a custom header', $refused->exception->getMessage());
            self::assertSame($before, Session::query()->sole()->getAttributes());
        }
    }

    /**
     * Configure the guards: `api` keeps the default transport (the body field
     * or the header), and `admin` travels by cookie, scoped to `/auth`.
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

        $config->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);
    }

    /**
     * Sign the seeded identity in on the guard and return the refresh token:
     * the body application's from its pair, the cookie application's from the
     * cookie its pair carries.
     *
     * @param  string  $guard
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(string $guard): string
    {
        $this->seedIdentity();

        $tokens = $this->sessions($guard)->signIn('password', self::credentials())->session?->tokens;

        self::assertNotNull($tokens);

        $token = $tokens->refreshToken?->reveal() ?? $tokens->refreshCookie?->cookie()->getValue();

        self::assertIsString($token);

        return $token;
    }

    /**
     * Send a refresh request to the guard's route with the query string, form
     * body, headers and, when given, the cookie, sent as the browser sends it
     * (the route does not encrypt cookies).
     *
     * @param  string  $guard
     * @param  string  $query
     * @param  array<string, string>  $body
     * @param  array<string, string>  $headers
     * @param  ?string  $cookie
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function refresh(string $guard, string $query = '', array $body = [], array $headers = [], ?string $cookie = null): TestResponse
    {
        Auth::forgetGuards();

        $cookies = $cookie === null ? [] : [self::COOKIES[$guard] => $cookie];

        return $this->call('POST', '/auth/' . $guard . '/refresh' . $query, $body, $cookies, [], $this->transformHeadersToServerVars($headers));
    }

    /**
     * Refresh the guard's session with the token the request carries, and
     * answer with where it was read from and the rotated token, in the cookie
     * or the body as the application's transport says, or with the refusal's
     * reason; a request without a token is a bad request.
     *
     * @param  string  $guard
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function refreshRoute(string $guard): JsonResponse
    {
        $result = Auth::sessions($guard)->refresh(self::servedToken($guard), self::requestClient());

        if ($result === null) {
            return new JsonResponse(['reason' => null], 400);
        }

        $tokens = $result->session?->tokens;

        if ($tokens === null) {
            return new JsonResponse(['reason' => $result->reason?->value], 401);
        }

        $source = ['source' => $result->source?->value];

        return $tokens->refreshCookie?->attachTo(new JsonResponse($source)) ?? SecretResponse::json([...$source, 'refresh_token' => $tokens->refreshToken]);
    }
}
