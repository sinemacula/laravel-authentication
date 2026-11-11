<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * The cookie that carries a cookie application's refresh token to the browser.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshCookie
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $token
     * @param  string  $name
     * @param  string  $path
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** The refresh token the cookie carries. */
        private Secret $token,

        /** The application's cookie name. */
        public string $name,

        /** The path the cookie is scoped to, which every route that reads it lives under. */
        public string $path,

        /** When the cookie expires: when the session ends. */
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * The `Set-Cookie` the browser keeps, revealing the token into it.
     *
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    public function cookie(): Cookie
    {
        return new Cookie($this->name, $this->token->reveal(), $this->expiresAt, $this->path, null, true, true, false, Cookie::SAMESITE_STRICT);
    }

    /**
     * Add the cookie to the response and mark the response not to be stored.
     *
     * @template TResponse of \Symfony\Component\HttpFoundation\Response
     *
     * @param  TResponse  $response
     * @return TResponse
     */
    public function attachTo(Response $response): Response
    {
        $response->headers->setCookie($this->cookie());

        return SecretResponse::withoutStoring($response);
    }
}
