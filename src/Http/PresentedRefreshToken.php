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
 * `RefreshTokenTransport::extract()` and `read()` build one from a request; an
 * application whose service layer keeps HTTP out may build one from the facts
 * its controller copied from the request, as its trusted description of that
 * request, as a `ClientContext` built from plain values is. Whoever built it,
 * the session service judges it again (`RefreshTokenTransport::judge()`) before
 * acting on it: a token in more than one carrier, or facts that do not show it
 * alone in its source, is a conflict, a source that is not the application's
 * transport a mismatch, and a cookie without the same-site facts cross-site.
 * Copy the facts from each request, never constants.
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
}
