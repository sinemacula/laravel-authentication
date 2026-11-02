<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * A refresh token a request carried, held as a secret, with where it carried
 * it: the cookie of a cookie application, or the body field or header of a body
 * application.
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
