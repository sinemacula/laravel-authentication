<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * An access token a session's issuer signed, with when it expires as it says:
 * its `exp`, and its lifetime in seconds, `exp` minus `iat`, read from the very
 * claims signed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IssuedAccessToken
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $token
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  int  $expiresIn
     */
    public function __construct(

        /** The access token. */
        public Secret $token,

        /** When it expires: its `exp`, in the issue time's timezone. */
        public CarbonImmutable $expiresAt,

        /** Its lifetime in seconds: `exp` minus `iat`. */
        public int $expiresIn,
    ) {}
}
