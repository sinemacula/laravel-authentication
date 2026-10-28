<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenSettings;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use Symfony\Component\HttpFoundation\Cookie;
use Tests\Unit\Stubs\PlainDeviceFixture;

/**
 * Unit tests for reading a refresh token through the one source a guard allows:
 * the sources it does not list are never read, a token carried twice is a
 * conflict, and a cookie must pass the cross-site checks; and for the cookies
 * that carry the token to a browser and clear it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenTransport::class)]
#[CoversClass(PresentedRefreshToken::class)]
final class RefreshTokenTransportTest extends TestCase
{
    /** @var string A refresh token, as opaque to the transport as any other value. */
    private const string TOKEN = 'header.payload.signature';

    /** @var string The cookie the guard reads. */
    private const string COOKIE = '__Secure-refresh_token';

    /** @var string An origin the guard allows besides the request's own. */
    private const string ALLOWED_ORIGIN = 'https://app.example.test';

    /**
     * A request that carries no token in any allowed source presents nothing.
     *
     * @return void
     */
    public function testARequestWithoutATokenPresentsNothing(): void
    {
        self::assertNull(self::transport()->read(Request::create('/auth/refresh', 'POST')));
    }

    /**
     * Rows of `[the request, the source it carries the token in]`.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request, 1: \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource}>
     */
    public static function provideCarriedTokens(): iterable
    {
        yield 'a JSON body' => [static fn (): Request => self::json(['refresh_token' => self::TOKEN]), RefreshTokenSource::BODY];
        yield 'a form body' => [static fn (): Request => Request::create('/auth/refresh', 'POST', ['refresh_token' => self::TOKEN]), RefreshTokenSource::BODY];
        yield 'a header' => [static fn (): Request => self::withHeaders(['X-Refresh-Token' => self::TOKEN]), RefreshTokenSource::HEADER];
        yield 'the cookie from the own origin' => [static fn (): Request => self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest'), RefreshTokenSource::COOKIE];
        yield 'the cookie from an allowed origin' => [static fn (): Request => self::cookie(self::TOKEN, self::ALLOWED_ORIGIN, 'fetch'), RefreshTokenSource::COOKIE];
    }

    /**
     * A token in one allowed source is presented with that source.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return void
     */
    #[DataProvider('provideCarriedTokens')]
    public function testATokenInOneAllowedSourceIsPresentedWithIt(\Closure $request, RefreshTokenSource $source): void
    {
        $presented = self::transport(['cookie', 'body', 'header'])->read($request());

        self::assertInstanceOf(PresentedRefreshToken::class, $presented);
        self::assertSame(self::TOKEN, $presented->token);
        self::assertSame($source, $presented->source);
    }

    /**
     * Rows of `[the request]` that carry a token only where the guard does not
     * read one.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request}>
     */
    public static function provideUnreadPlaces(): iterable
    {
        yield 'the query string of a POST' => [static fn (): Request => Request::create('/auth/refresh?refresh_token=' . self::TOKEN, 'POST')];
        yield 'the query string of a GET' => [static fn (): Request => Request::create('/auth/refresh', 'GET', ['refresh_token' => self::TOKEN])];
        yield 'the cookie, not a source' => [static fn (): Request => self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest')];
        yield 'another body field' => [static fn (): Request => self::json(['token' => self::TOKEN])];
    }

    /**
     * A token anywhere the guard does not read one is not presented: never the
     * query string, and no source the guard does not list.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @return void
     */
    #[DataProvider('provideUnreadPlaces')]
    public function testATokenWhereTheGuardDoesNotReadIsNotPresented(\Closure $request): void
    {
        self::assertNull(self::transport()->read($request()));
    }

    /**
     * Rows of `[the request]` that carry a token in two allowed sources.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request}>
     */
    public static function provideConflicts(): iterable
    {
        yield 'the same token in the body and a header' => [static fn (): Request => self::json(['refresh_token' => self::TOKEN], ['X-Refresh-Token' => self::TOKEN])];
        yield 'different tokens in the body and a header' => [static fn (): Request => self::json(['refresh_token' => self::TOKEN], ['X-Refresh-Token' => 'other'])];
        yield 'the cookie and the body' => [static fn (): Request => self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest', ['refresh_token' => self::TOKEN])];
        yield 'an empty header beside the body' => [static fn (): Request => self::json(['refresh_token' => self::TOKEN], ['X-Refresh-Token' => ''])];
    }

    /**
     * A token in more than one allowed source is a conflict, whether or not the
     * tokens are equal, so the server never picks one.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @return void
     */
    #[DataProvider('provideConflicts')]
    public function testATokenInMoreThanOneSourceIsAConflict(\Closure $request): void
    {
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport(['cookie', 'body', 'header'])->read($request()));
    }

    /**
     * Rows of `[the request]` that carry something other than one non-empty
     * string where the token goes.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request}>
     */
    public static function provideInvalidValues(): iterable
    {
        yield 'an empty body field' => [static fn (): Request => self::json(['refresh_token' => ''])];
        yield 'a null body field' => [static fn (): Request => self::json(['refresh_token' => null])];
        yield 'an array body field' => [static fn (): Request => self::json(['refresh_token' => [self::TOKEN]])];
        yield 'a number body field' => [static fn (): Request => self::json(['refresh_token' => 42])];
        yield 'an empty header' => [static fn (): Request => self::withHeaders(['X-Refresh-Token' => ''])];
        yield 'a header sent twice' => [static function (): Request {
            $request = Request::create('/auth/refresh', 'POST');
            $request->headers->set('X-Refresh-Token', [self::TOKEN, self::TOKEN]);

            return $request;
        }];
        yield 'an empty cookie' => [static fn (): Request => self::cookie('', 'http://localhost', 'XMLHttpRequest')];
        yield 'a cookie that could not be decrypted' => [static fn (): Request => self::cookie(null, 'http://localhost', 'XMLHttpRequest')];
        yield 'an array cookie' => [static fn (): Request => self::cookie([self::TOKEN], 'http://localhost', 'XMLHttpRequest')];
    }

    /**
     * A value that is not one non-empty string is an invalid token.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @return void
     */
    #[DataProvider('provideInvalidValues')]
    public function testAValueThatIsNotOneNonEmptyStringIsInvalid(\Closure $request): void
    {
        self::assertSame(FailureReason::TOKEN_INVALID, self::transport(['cookie', 'body', 'header'])->read($request()));
    }

    /**
     * Rows of `[the Origin header, the custom header]` a cookie refresh is
     * refused for.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideCrossSiteRequests(): iterable
    {
        yield 'no origin' => [null, 'XMLHttpRequest'];
        yield 'another origin' => ['https://evil.example.test', 'XMLHttpRequest'];
        yield 'an opaque origin' => ['null', 'XMLHttpRequest'];
        yield 'the own origin on another scheme' => ['https://localhost', 'XMLHttpRequest'];
        yield 'no custom header' => ['http://localhost', null];
        yield 'an empty custom header' => [self::ALLOWED_ORIGIN, ''];
    }

    /**
     * A cookie refresh without the request's own or an allowed origin, or
     * without the custom header, is refused as cross-site before its value is
     * looked at.
     *
     * @param  ?string  $origin
     * @param  ?string  $csrf
     * @return void
     */
    #[DataProvider('provideCrossSiteRequests')]
    public function testACookieRefreshMustBeSameSite(?string $origin, ?string $csrf): void
    {
        self::assertSame(FailureReason::CROSS_SITE_REQUEST, self::transport(['cookie'])->read(self::cookie('', $origin, $csrf)));
    }

    /**
     * The guard's own body field, header and CSRF header names are the ones
     * read.
     *
     * @return void
     */
    public function testTheConfiguredNamesAreRead(): void
    {
        $transport = new RefreshTokenTransport(new RefreshTokenSettings(
            [RefreshTokenSource::BODY, RefreshTokenSource::HEADER, RefreshTokenSource::COOKIE],
            'token',
            'X-Token',
            'refresh',
            '/auth',
            null,
            [],
            'X-CSRF',
        ));

        $cookie = Request::create('/auth/refresh', 'POST', [], ['refresh' => self::TOKEN], [], ['HTTP_ORIGIN' => 'http://localhost', 'HTTP_X_CSRF' => '1']);

        self::assertSame(RefreshTokenSource::BODY, self::presented($transport->read(self::json(['token' => self::TOKEN])))->source);
        self::assertSame(RefreshTokenSource::HEADER, self::presented($transport->read(self::withHeaders(['X-Token' => self::TOKEN])))->source);
        self::assertSame(RefreshTokenSource::COOKIE, self::presented($transport->read($cookie))->source);
        self::assertNull($transport->read(self::json(['refresh_token' => self::TOKEN])));
    }

    /**
     * Reading changes nothing on the request.
     *
     * @return void
     */
    public function testReadingHasNoSideEffects(): void
    {
        $request = self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest');
        $before  = [$request->cookies->all(), $request->headers->all(), $request->request->all()];

        self::transport(['cookie'])->read($request);

        self::assertSame($before, [$request->cookies->all(), $request->headers->all(), $request->request->all()]);
    }

    /**
     * The transport of a guard is built from the configuration.
     *
     * @return void
     */
    public function testTheTransportOfAGuardIsBuiltFromTheConfiguration(): void
    {
        $config = new ConfigRepository([
            'auth'           => ['guards' => ['api' => ['driver' => 'jwt', 'refresh_token' => ['sources' => ['header'], 'header' => 'X-Token']]]],
            'authentication' => ['refresh_token' => ['sources' => ['body'], 'body_field' => 'refresh_token', 'header' => 'X-Refresh-Token', 'cookie' => [
                'name' => 'refresh', 'path' => null, 'domain' => null, 'allowed_origins' => [], 'csrf_header' => 'X-Requested-With',
            ]]],
        ]);

        $transport = RefreshTokenTransport::forGuard('api', $config);

        self::assertSame(RefreshTokenSource::HEADER, self::presented($transport->read(self::withHeaders(['X-Token' => self::TOKEN])))->source);
        self::assertNull($transport->read(self::json(['refresh_token' => self::TOKEN])));
    }

    /**
     * Rows of `[seconds to the idle deadline, seconds to the absolute one]`:
     * the cookie expires at whichever comes first.
     *
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function provideDeadlines(): iterable
    {
        yield 'the idle deadline first' => [3600, 7200];
        yield 'the absolute deadline first' => [7200, 3600];
    }

    /**
     * The refresh cookie carries the token `HttpOnly`, `Secure` and
     * `SameSite=Strict`, with the guard's name, path and domain, and expires
     * when the device's session ends.
     *
     * @param  int  $idle
     * @param  int  $absolute
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testTheCookieCarriesTheTokenUntilTheSessionEnds(int $idle, int $absolute): void
    {
        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        try {
            $cookie = self::cookieTransport('.example.test')->cookie(self::TOKEN, new PlainDeviceFixture('device-1', $now->addSeconds($idle), $now->addSeconds($absolute)));
        } finally {
            Carbon::setTestNow();
        }

        self::assertSame(self::COOKIE, $cookie->getName());
        self::assertSame(self::TOKEN, $cookie->getValue());
        self::assertSame('/auth', $cookie->getPath());
        self::assertSame('.example.test', $cookie->getDomain());
        self::assertSame($now->getTimestamp() + 3600, $cookie->getExpiresTime());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame(Cookie::SAMESITE_STRICT, $cookie->getSameSite());
        self::assertFalse($cookie->isRaw());
    }

    /**
     * A device whose session has ended, or that has no deadlines, gets no
     * cookie.
     *
     * @return void
     */
    public function testAnEndedSessionGetsNoCookie(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot set a refresh cookie for a device whose session has ended or that has no idle and absolute deadlines.');

        self::cookieTransport()->cookie(self::TOKEN, new PlainDeviceFixture('device-1'));
    }

    /**
     * The clearing cookie has the same name, path and domain, no value, and has
     * already expired.
     *
     * @return void
     */
    public function testTheClearingCookieMatchesTheCookieAndHasExpired(): void
    {
        $cookie = self::cookieTransport(null)->forgetCookie();

        self::assertSame(self::COOKIE, $cookie->getName());
        self::assertNull($cookie->getValue());
        self::assertSame('/auth', $cookie->getPath());
        self::assertNull($cookie->getDomain());
        self::assertTrue($cookie->isCleared());
        self::assertLessThan(time(), $cookie->getExpiresTime());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame(Cookie::SAMESITE_STRICT, $cookie->getSameSite());
    }

    /**
     * Rows of `[setting or clearing the cookie]`.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Http\RefreshTokenTransport): \Symfony\Component\HttpFoundation\Cookie}>
     */
    public static function provideCookieCalls(): iterable
    {
        $device = new PlainDeviceFixture('device-1', Carbon::now()->addHour(), Carbon::now()->addHours(2));

        yield 'setting it' => [static fn (RefreshTokenTransport $transport): Cookie => $transport->cookie(self::TOKEN, $device)];
        yield 'clearing it' => [static fn (RefreshTokenTransport $transport): Cookie => $transport->forgetCookie()];
    }

    /**
     * A guard that does not read the cookie neither sets nor clears one, even
     * with a path configured: a cookie it never reads must not be set.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Http\RefreshTokenTransport): \Symfony\Component\HttpFoundation\Cookie  $call
     * @return void
     */
    #[DataProvider('provideCookieCalls')]
    public function testAGuardThatDoesNotReadTheCookieSetsNone(\Closure $call): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('does not read its refresh token from the cookie: add `cookie` to its `refresh_token.sources` and set `refresh_token.cookie.path`.');

        $call(self::transport());
    }

    /**
     * A transport that reads only the cookie, scoped to `/auth` and the domain.
     *
     * @param  ?string  $domain
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     */
    private static function cookieTransport(?string $domain = null): RefreshTokenTransport
    {
        $settings = new RefreshTokenSettings([RefreshTokenSource::COOKIE], 'refresh_token', 'X-Refresh-Token', self::COOKIE, '/auth', $domain, [], 'X-Requested-With');

        return new RefreshTokenTransport($settings);
    }

    /**
     * A transport reading the given sources with the default names, the cookie
     * scoped to `/auth` and one allowed origin besides the request's own.
     *
     * @param  list<string>  $sources
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     */
    private static function transport(array $sources = ['body', 'header']): RefreshTokenTransport
    {
        return new RefreshTokenTransport(new RefreshTokenSettings(
            array_map(RefreshTokenSource::from(...), $sources),
            'refresh_token',
            'X-Refresh-Token',
            self::COOKIE,
            '/auth',
            null,
            [self::ALLOWED_ORIGIN],
            'X-Requested-With',
        ));
    }

    /**
     * A JSON refresh request with the body and headers.
     *
     * @param  array<string, mixed>  $body
     * @param  array<string, string>  $headers
     * @return \Illuminate\Http\Request
     *
     * @throws \JsonException
     */
    private static function json(array $body, array $headers = []): Request
    {
        $request = Request::create('/auth/refresh', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR));
        $request->headers->add($headers);

        return $request;
    }

    /**
     * A refresh request with no body and the headers.
     *
     * @param  array<string, string>  $headers
     * @return \Illuminate\Http\Request
     */
    private static function withHeaders(array $headers): Request
    {
        $request = Request::create('/auth/refresh', 'POST');
        $request->headers->add($headers);

        return $request;
    }

    /**
     * A refresh request carrying the cookie with the value, from the origin
     * with the custom header (each omitted when `null`), and the form body.
     *
     * @param  mixed  $value
     * @param  ?string  $origin
     * @param  ?string  $csrf
     * @param  array<string, mixed>  $body
     * @return \Illuminate\Http\Request
     */
    private static function cookie(mixed $value, ?string $origin, ?string $csrf, array $body = []): Request
    {
        $server = array_filter(['HTTP_ORIGIN' => $origin, 'HTTP_X_REQUESTED_WITH' => $csrf], static fn (?string $header): bool => $header !== null);

        return Request::create('/auth/refresh', 'POST', $body, [self::COOKIE => $value], [], $server);
    }

    /**
     * Narrow a read to the token it presented.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $read
     * @return \SineMacula\Laravel\Authentication\Http\PresentedRefreshToken
     */
    private static function presented(FailureReason|PresentedRefreshToken|null $read): PresentedRefreshToken
    {
        self::assertInstanceOf(PresentedRefreshToken::class, $read);

        return $read;
    }
}
