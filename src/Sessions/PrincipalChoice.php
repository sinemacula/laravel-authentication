<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * A sign-in waiting for the identity to choose the principal its session acts
 * as: the credential that continues it, who it is for, and the principals it
 * may choose from.
 *
 * The token is opaque and is not a JWT, so no guard authenticates a request
 * with it. It works once, for the guard that issued it, until `$expiresAt`:
 * `choose()` uses it up whatever the outcome. The principals are the eligible
 * ones when the choice was issued or looked up; `choose()` checks the chosen
 * one again.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PrincipalChoice
{
    /**
     * Constructor.
     *
     * @param  string  $token
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @param  string  $method
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** The credential that continues the sign-in with the chosen principal. */
        #[\SensitiveParameter] public string $token,

        /** Guard the sign-in is for. */
        public string $guard,

        /** Identity the sign-in method verified. */
        public Identity $identity,

        /** The principals the identity may choose from. */
        public array $principals,

        /** Name of the sign-in method that verified the identity. */
        public string $method,

        /** When the choice stops working. */
        public CarbonImmutable $expiresAt,
    ) {}
}
