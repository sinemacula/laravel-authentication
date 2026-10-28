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
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * End-to-end tests for refreshing with the token a request carries, through a
 * route on a real database: each guard reads its token from the sources it
 * lists and no other, a token carried twice or a cookie sent cross-site is
 * refused without touching the device, and the result says where the token came
 * from.
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

    /** @var string The cookie the `admin` guard reads its refresh token from. */
    private const string COOKIE = '__Secure-refresh_token';

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

        Route::post('/auth/{guard}/refresh', static function (string $guard): JsonResponse {
            $jwt = Auth::manager()->guard($guard);

            assert($jwt instanceof JwtGuard);

            $result = $jwt->refreshFromRequest();

            return match (true) {
                $result instanceof RefreshResult => new JsonResponse(['source' => $result->source?->value, 'refresh_token' => $result->refreshToken]),
                $result === null                 => new JsonResponse(['reason' => null], 400),
                default                          => new JsonResponse(['reason' => $result->value], 401),
            };
        });
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
     * Rows of `[the guard, the request's query string, body, headers and
     * cookie]` that carry the token only where the guard does not read one.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: bool, 3: bool, 4: bool}>
     */
    public static function provideUnreadPlaces(): iterable
    {
        yield 'the query string' => ['api', true, false, false, false];
        yield 'the cookie, for a guard that does not read it' => ['api', false, false, false, true];
        yield 'the body, for a guard that reads only the cookie' => ['admin', false, true, false, false];
        yield 'a header, for a guard that reads only the cookie' => ['admin', false, false, true, false];
    }

    /**
     * A token where the guard does not read one is not seen: nothing is
     * attempted and nothing is dispatched.
     *
     * @param  string  $guard
     * @param  bool  $query
     * @param  bool  $body
     * @param  bool  $header
     * @param  bool  $cookie
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnreadPlaces')]
    public function testATokenWhereTheGuardDoesNotReadIsNotSeen(string $guard, bool $query, bool $body, bool $header, bool $cookie): void
    {
        $token = $this->signIn($guard);

        $this->recordEvents([AuthenticationFailed::class, Refreshed::class]);

        $this->refresh(
            $guard,
            $query ? '?refresh_token=' . $token : '',
            $body ? ['refresh_token' => $token] : [],
            [...($header ? ['X-Refresh-Token' => $token] : []), 'Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest'],
            $cookie ? $token : null,
        )->assertStatus(400);

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
        yield 'the cookie without the custom header' => ['admin', false, ['Origin' => 'http://localhost'], true, FailureReason::CROSS_SITE_REQUEST];
        yield 'the cookie from another origin' => ['admin', false, ['Origin' => 'https://evil.test', 'X-Requested-With' => '1'], true, FailureReason::CROSS_SITE_REQUEST];
        yield 'the cookie without an origin' => ['admin', false, ['X-Requested-With' => 'XMLHttpRequest'], true, FailureReason::CROSS_SITE_REQUEST];
    }

    /**
     * A request the transport refuses is answered with its reason and reported
     * as a failed refresh, and leaves the device as it was: its token still
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
    public function testARefusedRequestLeavesTheDeviceAsItWas(string $guard, bool $body, array $headers, bool $cookie, FailureReason $reason): void
    {
        $token  = $this->signIn($guard);
        $before = Device::query()->sole()->getAttributes();

        $this->recordEvents([AuthenticationFailed::class]);

        $headers = array_map(static fn (string $value): string => $value === 'token' ? $token : $value, $headers);

        $this->refresh($guard, '', $body ? ['refresh_token' => $token] : [], $headers, $cookie ? $token : null)
            ->assertUnauthorized()
            ->assertJson(['reason' => $reason->value]);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::REFRESH, $failure->flow);
        self::assertSame($reason, $failure->reason);
        self::assertSame($guard, $failure->context->guard);
        self::assertSame($before, Device::query()->sole()->getAttributes());

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
        yield 'the same name' => ['__Secure-refresh_token'];
        yield 'a name with a dot' => ['__Secure-refresh.token'];
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
        $before = Device::query()->sole()->getAttributes();

        $this->recordEvents([AuthenticationFailed::class, Refreshed::class]);

        $headers = ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest', 'Cookie' => $planted . '=planted; ' . self::COOKIE . '=' . $token];

        $this->refresh('admin', '', [], $headers, 'planted')
            ->assertUnauthorized()
            ->assertJson(['reason' => FailureReason::REFRESH_TOKEN_CONFLICT->value]);

        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($before, Device::query()->sole()->getAttributes());

        $this->refresh('admin', '', [], ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest', 'Cookie' => self::COOKIE . '=' . $token], $token)
            ->assertOk()
            ->assertJson(['source' => 'cookie']);
    }

    /**
     * A package-wide `__Host-` cookie name binds only the guard that reads the
     * cookie: that guard refreshes from it on the root path, and a guard that
     * reads the body or a header refreshes as before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHostCookieNameLeavesTheGuardsThatDoNotReadTheCookieAlone(): void
    {
        config()->set([
            'authentication.refresh_token.cookie.name' => '__Host-refresh_token',
            'auth.guards.admin.refresh_token'          => ['sources' => ['cookie'], 'cookie' => ['path' => '/']],
        ]);

        $api = $this->signIn('api');

        $this->refresh('api', '', ['refresh_token' => $api])->assertOk()->assertJson(['source' => 'body']);

        $admin = $this->sessions('admin')->signIn('password', self::credentials())->session;

        self::assertNotNull($admin);

        Auth::forgetGuards();

        $headers = $this->transformHeadersToServerVars(['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest']);

        $this->call('POST', '/auth/admin/refresh', [], ['__Host-refresh_token' => $admin->tokens->refreshToken], [], $headers)
            ->assertOk()
            ->assertJson(['source' => 'cookie']);
    }

    /**
     * A cookie refresh from the request's own origin with the custom header is
     * exchanged and the result says it came from the cookie.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieRefreshFromTheOwnOriginIsExchanged(): void
    {
        $token = $this->signIn('admin');

        $this->refresh('admin', '', [], ['Origin' => 'http://localhost', 'X-Requested-With' => 'XMLHttpRequest'], $token)
            ->assertOk()
            ->assertJson(['source' => 'cookie']);
    }

    /**
     * Configure the guards: `api` reads the defaults (body and header), and
     * `admin` reads only the cookie, scoped to `/auth`.
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

        $config->set('auth.guards.admin.refresh_token', ['sources' => ['cookie'], 'cookie' => ['path' => '/auth']]);
    }

    /**
     * Sign the seeded identity in on the guard and return the refresh token.
     *
     * @param  string  $guard
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(string $guard): string
    {
        $this->seedIdentity();

        $session = $this->sessions($guard)->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session->tokens->refreshToken;
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

        $cookies = $cookie === null ? [] : [self::COOKIE => $cookie];

        return $this->call('POST', '/auth/' . $guard . '/refresh' . $query, $body, $cookies, [], $this->transformHeadersToServerVars($headers));
    }
}
