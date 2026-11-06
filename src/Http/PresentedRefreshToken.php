<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * A refresh token a request carried, held as a secret, with where it carried it
 * (the cookie of a cookie application, or the body field or header of a body
 * application) and every carrier the request carried a refresh token in.
 *
 * `RefreshTokenTransport::extract()` builds one from a request, and is the way
 * a controller should take one. An application may instead build one as its
 * trusted description of a request it read itself, as a `ClientContext` built
 * from plain values is: `fromBody()` for the token a body application's own
 * code read from its body, the constructor for any other. Whoever built it, the
 * session service judges it again (`RefreshTokenTransport::judge()`) before
 * acting on it: a token in more than one carrier, or facts that do not show it
 * alone in its source, is a conflict, a source that is not the application's
 * transport a mismatch (a body token on a cookie application), and a cookie
 * without the same-site facts cross-site. It is judged on the facts given and
 * cannot show facts left out, as a cookie or header the request carried beside
 * the body, which `extract()` would have refused as a conflict: copy the facts
 * from each request, never constants.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PresentedRefreshToken
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $token
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>  $carriers
     */
    public function __construct(

        /** The refresh token, as the request carried it. */
        public Secret $token,

        /** Where the request carried it. */
        public RefreshTokenSource $source,

        /** Every carrier the request carried a refresh token in, whatever its value, once per token: the cookie as often as the request's `Cookie` headers carried it. */
        public array $carriers,
    ) {}

    /**
     * The refresh token a body application's own code read from its request's
     * body, as its trusted description of that request: presented from the
     * body, the only carrier. An empty token is refused
     * (`InvalidArgumentException`). A cookie application never takes one: its
     * token travels only in its cookie, so the session service refuses one as
     * `refresh_transport_mismatch`.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $token
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromBody(#[\SensitiveParameter] Secret|string $token): self
    {
        return new self($token instanceof Secret ? $token : new Secret($token), RefreshTokenSource::BODY, [RefreshTokenSource::BODY]);
    }
}
