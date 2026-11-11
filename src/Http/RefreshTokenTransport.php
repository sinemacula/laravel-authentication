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
 * An application's refresh token transport: extracts the refresh token a
 * request carries, judges a presented one, and hands a cookie application's
 * tokens to the browser in the cookie.
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
     * Extract the refresh token the request carries, or why it cannot be read,
     * or `null` when it carries none.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null
     */
    public function extract(Request $request): FailureReason|PresentedRefreshToken|null
    {
        $source = $this->carrier($request);

        return $source instanceof RefreshTokenSource ? $this->presented($request, $source) : $source;
    }

    /**
     * Judge a presented refresh token against the application's transport and
     * the client, or `null` when it passes.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\PresentedRefreshToken  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public function judge(#[\SensitiveParameter] PresentedRefreshToken $presented, ClientContext $client): ?FailureReason
    {
        $source = $presented->source;

        return match (true) {
            $presented->carriers !== [$source]                                          => FailureReason::REFRESH_TOKEN_CONFLICT,
            !$this->isCarrier($source)                                                  => FailureReason::REFRESH_TRANSPORT_MISMATCH,
            $source === RefreshTokenSource::COOKIE && !$this->isSameSiteClient($client) => FailureReason::CROSS_SITE_REQUEST,
            default                                                                     => null,
        };
    }

    /**
     * The pair as the application's transport hands it out, a cookie
     * application's refresh token moved into its cookie.
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
     * already expired.
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
     * Whether the request came from a page of the API's own site.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    public function isSameSiteRequest(Request $request): bool
    {
        return $this->isSameSiteClient(ClientContext::sameSiteFactsOf($request));
    }

    /**
     * Whether the client came from a page of the API's own site: it carried the
     * CSRF header and an `Origin` that is its own or an allowed one.
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
     * When the session ends, read on the write connection as the refresh
     * token's own `exp` is.
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
     * The cookie's path, or a `LogicException` for a body application.
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
     * The one carrier the request carries a refresh token in, why it has none
     * to read, or `null` when no carrier carries one.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource|null
     */
    private function carrier(Request $request): FailureReason|RefreshTokenSource|null
    {
        $present = array_values(array_filter(RefreshTokenSource::cases(), fn (RefreshTokenSource $source): bool => $this->carries($request, $source)));

        if (in_array(RefreshTokenSource::COOKIE, $present, true) && $this->cookiesNamed($request) > 1) {
            return FailureReason::REFRESH_TOKEN_CONFLICT;
        }

        if (count($present) !== 1) {
            return $present === [] ? null : FailureReason::REFRESH_TOKEN_CONFLICT;
        }

        [$source] = $present;

        return ($source === RefreshTokenSource::COOKIE) !== $this->usesCookie() ? FailureReason::REFRESH_TRANSPORT_MISMATCH : $source;
    }

    /**
     * Whether the source is one the application's transport reads a refresh
     * token from.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return bool
     */
    private function isCarrier(RefreshTokenSource $source): bool
    {
        return match ($source) {
            RefreshTokenSource::COOKIE => $this->usesCookie(),
            RefreshTokenSource::BODY   => !$this->usesCookie(),
            RefreshTokenSource::HEADER => !$this->usesCookie() && $this->settings->header !== null,
        };
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
     * cookie's name, each name read as PHP files it.
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

        return is_string($value) && $value !== '' ? new PresentedRefreshToken(new Secret($value), $source, [$source]) : FailureReason::TOKEN_INVALID;
    }
}
