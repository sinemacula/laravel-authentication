<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;

/**
 * Reads a refresh token from a request through the one source a guard allows.
 *
 * A guard's `refresh_token` settings list the sources it reads: the cookie, a
 * body field (the JSON or form body, never the query string) and a header. Only
 * those are read, and a request that carries a token in more than one of them
 * is refused, equal or not, so a request cannot pass the cookie's cross-site
 * checks by also sending the token another way, nor leave the server to choose
 * which one counts. A token read from the cookie, which a browser attaches by
 * itself, must come with an `Origin` that is the request's own or an allowed
 * one, and with the custom header, which a cross-site form cannot send.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshTokenTransport
{
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
     * carries one, `refresh_token_conflict` when more than one does,
     * `cross_site_request` when it is in the cookie without an allowed origin
     * and the custom header, and `token_invalid` when the value is not a
     * non-empty string. Reading has no side effects.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null
     */
    public function read(Request $request): FailureReason|PresentedRefreshToken|null
    {
        $present = array_values(array_filter($this->settings->sources, fn (RefreshTokenSource $source): bool => $this->carries($request, $source)));

        if (count($present) !== 1) {
            return $present === [] ? null : FailureReason::REFRESH_TOKEN_CONFLICT;
        }

        return $present[0] === RefreshTokenSource::COOKIE && !$this->isSameSite($request)
            ? FailureReason::CROSS_SITE_REQUEST
            : $this->presented($request, $present[0]);
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

        return count($values) === 1 && is_string($values[0]) && $values[0] !== ''
            ? new PresentedRefreshToken($values[0], $source)
            : FailureReason::TOKEN_INVALID;
    }

    /**
     * Whether a cookie refresh came from the request's own origin or an allowed
     * one, with the custom header set.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    private function isSameSite(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        $csrf   = $request->headers->get($this->settings->csrfHeader);

        if ($csrf === null || $csrf === '') {
            return false;
        }

        return $origin === $request->getSchemeAndHttpHost() || in_array($origin, $this->settings->allowedOrigins, true);
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
