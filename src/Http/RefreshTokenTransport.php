<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Reads a refresh token from a request through the one source a guard allows.
 *
 * A guard's `refresh_token` settings list the sources it reads: the cookie, a
 * body field (the JSON or form body, never the query string) and a header. Only
 * those are read, and a request that carries a token in more than one of them,
 * or two cookies of the refresh cookie's name, is refused, equal or not, so a
 * request cannot pass the cookie's cross-site checks by also sending the token
 * another way, nor leave the server to choose which one counts. A token read
 * from the cookie, which a browser attaches by itself, must come with an
 * `Origin` that is the request's own or an allowed one, and with the custom
 * header, which a cross-site form cannot send.
 *
 * It also makes the cookie that carries a browser's refresh token, and the one
 * that clears it, for the application to attach to its own responses: the token
 * lives only in the browser, so the API stays stateless.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshTokenTransport
{
    /** @var string Why a guard that does not read the cookie neither sets nor clears it. */
    private const string NOT_A_COOKIE_GUARD = 'This guard does not read its refresh token from the cookie:'
        . ' add `cookie` to its `refresh_token.sources` and set `refresh_token.cookie.path`.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenSettings  $settings
     */
    public function __construct(

        /** The guard's transport settings. */
        private RefreshTokenSettings $settings,
    ) {}

    /**
     * The transport of the guard, from the configuration.
     *
     * @param  string  $guard
     * @param  \Illuminate\Config\Repository  $config
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function forGuard(string $guard, ConfigRepository $config): self
    {
        return new self(RefreshTokenSettings::forGuard($guard, $config));
    }

    /**
     * Read the refresh token the request carries: `null` when no allowed source
     * carries one, `refresh_token_conflict` when more than one does or the
     * request carries the cookie twice, `cross_site_request` when it is in the
     * cookie without an allowed origin and the custom header, and
     * `token_invalid` when the value is not a non-empty string. Reading has no
     * side effects.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null
     */
    public function read(Request $request): FailureReason|PresentedRefreshToken|null
    {
        $present = array_values(array_filter($this->settings->sources, fn (RefreshTokenSource $source): bool => $this->carries($request, $source)));

        if (in_array(RefreshTokenSource::COOKIE, $present, true) && $this->cookiesNamed($request) > 1) {
            return FailureReason::REFRESH_TOKEN_CONFLICT;
        }

        if (count($present) !== 1) {
            return $present === [] ? null : FailureReason::REFRESH_TOKEN_CONFLICT;
        }

        [$source] = $present;

        return $source === RefreshTokenSource::COOKIE && !$this->isSameSiteRequest($request)
            ? FailureReason::CROSS_SITE_REQUEST
            : $this->presented($request, $source);
    }

    /**
     * The cookie that carries the refresh token to the browser: `HttpOnly`, so
     * scripts cannot read it, `Secure`, `SameSite=Strict`, with the guard's
     * name, path and domain, and expiring when the device's session ends (the
     * earlier of its deadlines, as the token itself does).
     *
     * @param  string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return \Symfony\Component\HttpFoundation\Cookie
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function cookie(#[\SensitiveParameter] string $refreshToken, Device $device): Cookie
    {
        return $this->makeCookie($refreshToken, self::sessionEnd($device));
    }

    /**
     * The cookie that clears the refresh cookie: the same name, path and
     * domain, already expired. Any response may carry it, a logout route
     * outside the cookie's path included, since a path limits where a browser
     * sends a cookie, not which response may set it.
     *
     * @return \Symfony\Component\HttpFoundation\Cookie
     *
     * @throws \LogicException
     */
    public function forgetCookie(): Cookie
    {
        return $this->makeCookie(null, Carbon::now()->subYear());
    }

    /**
     * Whether the request came from a page of the API's own site, as the
     * refresh cookie's checks require: its `Origin` is the request's own
     * (scheme and host) or one of the allowed origins, and it carries the
     * custom header with a value, which a cross-site form or simple request
     * cannot send. `read()` holds a token from the cookie to it; a route that
     * sets the cookie, a browser sign-in above all, must hold its request to it
     * too, or a cross-site form could sign the browser into another account.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    public function isSameSiteRequest(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        $csrf   = $request->headers->get($this->settings->csrfHeader);

        if ($csrf === null || $csrf === '') {
            return false;
        }

        return $origin === $request->getSchemeAndHttpHost() || in_array($origin, $this->settings->allowedOrigins, true);
    }

    /**
     * When the device's session ends, the earlier of its deadlines, read on the
     * write connection, as the refresh token's own `exp` is.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private static function sessionEnd(Device $device): CarbonImmutable
    {
        [$idle, $absolute] = WriteConnection::during($device, static fn (): ?array => TokenLifetimes::liveDeadlines($device, Carbon::now()))
            ?? throw new \InvalidArgumentException('Cannot set a refresh cookie for a device whose session has ended or that has no idle and absolute deadlines.');

        return CarbonImmutable::createFromTimestamp(min($idle->getTimestamp(), $absolute->getTimestamp()));
    }

    /**
     * A refresh cookie with the guard's name, path and domain and the browser
     * protections, or a `LogicException` when the guard does not read the
     * cookie: a cookie it would never read must not be set.
     *
     * @param  ?string  $value
     * @param  \DateTimeInterface  $expires
     * @return \Symfony\Component\HttpFoundation\Cookie
     *
     * @throws \LogicException
     */
    private function makeCookie(#[\SensitiveParameter] ?string $value, \DateTimeInterface $expires): Cookie
    {
        $path = (in_array(RefreshTokenSource::COOKIE, $this->settings->sources, true) ? $this->settings->cookiePath : null)
            ?? throw new \LogicException(self::NOT_A_COOKIE_GUARD);

        return new Cookie($this->settings->cookieName, $value, $expires, $path, $this->settings->cookieDomain, true, true, false, Cookie::SAMESITE_STRICT);
    }

    /**
     * Whether the request carries a token in the source, whatever its value.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return bool
     */
    private function carries(Request $request, RefreshTokenSource $source): bool
    {
        return match ($source) {
            RefreshTokenSource::COOKIE => $request->cookies->has($this->settings->cookieName),
            RefreshTokenSource::HEADER => $request->headers->has($this->settings->header),
            RefreshTokenSource::BODY   => array_key_exists($this->settings->bodyField, self::body($request)),
        };
    }

    /**
     * How many cookies the request's `Cookie` headers carry under the refresh
     * cookie's name, each name read as PHP files it: nothing from the first `[`
     * on when a `]` follows it, and a `.`, a space or an unclosed `[` as `_`.
     * PHP keeps only the first of the cookies it files under one name, and a
     * browser sends a cookie that another host of the site planted (with the
     * parent `Domain` and a longer `Path`) before the API's own, so the headers
     * are counted rather than the one cookie PHP kept.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return int
     */
    private function cookiesNamed(Request $request): int
    {
        $names = [];

        foreach ($request->headers->all('cookie') as $header) {
            foreach (explode(';', strtr((string) $header, ',', ';')) as $pair) {
                $names[] = strtr((string) preg_replace('/\[.*\].*/s', '', explode('=', ltrim($pair))[0]), '. [', '___');
            }
        }

        return count(array_keys($names, $this->settings->cookieName, true));
    }

    /**
     * The token the source carries, or `token_invalid` when it is not one
     * non-empty string.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken
     */
    private function presented(Request $request, RefreshTokenSource $source): FailureReason|PresentedRefreshToken
    {
        $values = match ($source) {
            RefreshTokenSource::COOKIE => [$request->cookies->all()[$this->settings->cookieName]],
            RefreshTokenSource::HEADER => $request->headers->all($this->settings->header),
            RefreshTokenSource::BODY   => [self::body($request)[$this->settings->bodyField]],
        };

        $value = count($values) === 1 ? reset($values) : null;

        return is_string($value) && $value !== '' ? new PresentedRefreshToken($value, $source) : FailureReason::TOKEN_INVALID;
    }

    /**
     * The request's body fields: the JSON body, or the form body of a request
     * that may have one; never the query string.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<array-key, mixed>
     */
    private static function body(Request $request): array
    {
        if ($request->isJson()) {
            return $request->json()->all();
        }

        return in_array($request->getRealMethod(), ['GET', 'HEAD'], true) ? [] : $request->request->all();
    }
}
