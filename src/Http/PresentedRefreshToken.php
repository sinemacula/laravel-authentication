<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * A refresh token a request carried, with where it carried it, so a refresh
 * read from the cookie can be answered with a cookie and one read from the body
 * or a header in the body.
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
     */
    public function __construct(

        /** The refresh token, as the request carried it. */
        public Secret $token,

        /** Where the request carried it. */
        public RefreshTokenSource $source,
    ) {}
}
