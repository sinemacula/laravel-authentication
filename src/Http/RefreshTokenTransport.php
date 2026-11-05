<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\Enums\Transport;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * An application's refresh token transport: reads the refresh token a request
 * carries, and hands a cookie application's tokens to the browser in the
 * cookie.
 *
 * An application's `refresh_token.transport` is `body` (the `body_field` of the
 * JSON or form body, never the query string, or the `header` when one is set)
 * or `cookie` (its `HttpOnly` refresh cookie). Every request is read in all
 * three carriers, whatever the transport: one that carries a token in more than
 * one of them, or the cookie twice, is refused as `refresh_token_conflict`,
 * equal or not, so a request cannot pass the cookie's cross-site checks by also
 * sending the token another way, nor leave the server to choose which one
 * counts; one that carries it only in a carrier that is not the application's
 * transport is refused as `refresh_transport_mismatch`. A token read from the
 * cookie, which a browser attaches by itself, must come with an `Origin` that
 * is the request's own or an allowed one, and with the custom header, which a
 * cross-site form cannot send; the session service holds every other path that
 * sets a cookie application's cookie from credentials or a pending session to
 * the same rule (`isSameSiteClient()`), so a cross-site form cannot sign the
 * browser into another account.
 *
 * For a cookie application, `deliver()` puts the refresh token of every pair a
 * sign-in, refresh, switch or activation issues into a `RefreshCookie`, so the
 * plain token never reaches the application's code; `forgetCookie()` makes the
 * cookie that clears it. The cookie is host-only, on the application's path,
 * and its name is the application's own, so two browser applications on one
 * host never overwrite each other's. The token lives only in the browser, so
 * the API stays stateless.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshTokenTransport
{
    /** @var string Why a body application neither sets nor clears the cookie. */
    private const string NOT_A_COOKIE_APPLICATION = 'This application\'s refresh token travels in the body:'
        . ' set its `refresh_token.transport` to `cookie`, and `refresh_token.cookie.path`, to use the cookie.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenSettings  $settings
     */
    public function __construct(

        /** The application's transport settings. */
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
     * Whether the application's refresh token travels in its cookie.
     *
     * @return bool
     */
    public function usesCookie(): bool
    {
        return $this->settings->transport === Transport::COOKIE;
    }

    /**
     * Read the refresh token the request carries: `null` when no carrier
     * carries one; `refresh_token_conflict` when more than one does or the
     * request carries the cookie twice; `refresh_transport_mismatch` when the
     * one that does is not the application's transport; `cross_site_request`
     * when it is in the cookie without an allowed origin and the custom header;
     * and `token_invalid` when the value is not a non-empty string. Reading has
     * no side effects.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null
     */
    public function read(Request $request): FailureReason|PresentedRefreshToken|null
    {
        $present = array_values(array_filter(RefreshTokenSource::cases(), fn (RefreshTokenSource $source): bool => $this->carries($request, $source)));

        if (in_array(RefreshTokenSource::COOKIE, $present, true) && $this->cookiesNamed($request) > 1) {
            return FailureReason::REFRESH_TOKEN_CONFLICT;
        }

        if (count($present) !== 1) {
            return $present === [] ? null : FailureReason::REFRESH_TOKEN_CONFLICT;
        }

        [$source] = $present;

        return match (true) {
            ($source === RefreshTokenSource::COOKIE) !== $this->usesCookie()              => FailureReason::REFRESH_TRANSPORT_MISMATCH,
            $source === RefreshTokenSource::COOKIE && !$this->isSameSiteRequest($request) => FailureReason::CROSS_SITE_REQUEST,
            default                                                                       => $this->presented($request, $source),
        };
    }

    /**
     * The pair as the application's transport hands it out: a body
     * application's as it is; a cookie application's with its refresh token
     * moved into the cookie that carries it, expiring when the session ends
     * (the earlier of its deadlines, read on the write connection, as the
     * token's own `exp` is). Only the session service delivers a pair.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenPair  $pair
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenPair
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public function deliver(TokenPair $pair, Session $session): TokenPair
    {
        if (!$this->usesCookie() || $pair->refreshToken === null) {
            return $pair;
        }

        return new TokenPair(
            accessToken: $pair->accessToken,
            expiresAt: $pair->expiresAt,
            expiresIn: $pair->expiresIn,
            refreshToken: null,
            refreshCookie: new RefreshCookie($pair->refreshToken, $this->cookieName(), $this->cookiePath(), self::sessionEnd($session)),
        );
    }

    /**
     * The cookie that clears the refresh cookie: the same name and path,
     * already expired. A route outside the cookie's path may send it, since a
     * path limits where a browser sends a cookie, not which response may set
     * it, though only a route under the path receives the cookie to sign out
     * by. Send it only for a request that signed its session out by its access
     * token, which a cross-site page cannot send, or that passes
     * `isSameSiteRequest()`: a response that clears it whatever the request
     * carried lets a cross-site form sign the browser out.
     * `signOutFromRequest()`'s result carries it on exactly those terms. A body
     * application has no cookie to clear (`LogicException`).
     *
     * @return \Symfony\Component\HttpFoundation\Cookie
     *
     * @throws \LogicException
     */
    public function forgetCookie(): Cookie
    {
        return new Cookie($this->cookieName(), null, Carbon::now()->subYear(), $this->cookiePath(), null, true, true, false, Cookie::SAMESITE_STRICT);
    }

    /**
     * Whether the request came from a page of the API's own site, as the
     * refresh cookie's checks require: `isSameSiteClient()` of the request's
     * client context. `read()` holds a token from the cookie to it, and the
     * session service holds every sign-in, start and pending-session action of
     * a cookie application to the same rule; an application's own route that
     * clears the cookie holds its request to it.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    public function isSameSiteRequest(Request $request): bool
    {
        return $this->isSameSiteClient(ClientContext::fromRequest($request));
    }

    /**
     * Whether the client came from a page of the API's own site: it carried the
     * custom header with a value, which a cross-site form or simple request
     * cannot send, and presented an `Origin` that is the request's own (scheme
     * and host) or one of the allowed origins. A fact the context lacks fails
     * the check, so a context built from plain values without them never
     * passes.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     */
    public function isSameSiteClient(ClientContext $client): bool
    {
        $origin = $client->origin;

        if ($origin === null || !$client->carriesHeader($this->settings->csrfHeader)) {
            return false;
        }

        return $origin === $client->schemeAndHost || in_array($origin, $this->settings->allowedOrigins, true);
    }

    /**
     * When the session ends, the earlier of its deadlines (the idle one alone
     * when it has no absolute one), read on the write connection, as the
     * refresh token's own `exp` is.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private static function sessionEnd(Session $session): CarbonImmutable
    {
        return WriteConnection::during($session, static fn (): ?CarbonImmutable => SessionDeadlines::liveEnd($session, Carbon::now()))
            ?? throw new \InvalidArgumentException('Cannot set a refresh cookie for a session that has ended or that has no idle deadline.');
    }

    /**
     * The cookie's name, or a `LogicException` for a body application whose
     * guard's name makes none.
     *
     * @return string
     *
     * @throws \LogicException
     */
    private function cookieName(): string
    {
        return $this->settings->cookieName ?? throw new \LogicException(self::NOT_A_COOKIE_APPLICATION);
    }

    /**
     * The cookie's path, or a `LogicException` for a body application: a cookie
     * it would never read must not be set.
     *
     * @return string
     *
     * @throws \LogicException
     */
    private function cookiePath(): string
    {
        return ($this->usesCookie() ? $this->settings->cookiePath : null) ?? throw new \LogicException(self::NOT_A_COOKIE_APPLICATION);
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
            RefreshTokenSource::COOKIE => $this->settings->cookieName !== null && $request->cookies->has($this->settings->cookieName),
            RefreshTokenSource::HEADER => $this->settings->header     !== null && $request->headers->has($this->settings->header),
            RefreshTokenSource::BODY   => array_key_exists($this->settings->bodyField, RequestBody::fields($request)),
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
            RefreshTokenSource::COOKIE => [$request->cookies->all()[$this->cookieName()]],
            RefreshTokenSource::HEADER => $request->headers->all((string) $this->settings->header),
            RefreshTokenSource::BODY   => [RequestBody::fields($request)[$this->settings->bodyField]],
        };

        $value = count($values) === 1 ? reset($values) : null;

        return is_string($value) && $value !== '' ? new PresentedRefreshToken(new Secret($value), $source) : FailureReason::TOKEN_INVALID;
    }
}
