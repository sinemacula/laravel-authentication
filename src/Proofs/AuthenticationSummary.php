<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;

/**
 * What an access token says about its session's authentication: when it last
 * authenticated (`auth_time`) and how (`amr`), both derived from the session's
 * proofs when the token is issued.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticationSummary
{
    /**
     * Constructor.
     *
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  list<string>  $methods
     */
    public function __construct(

        /** When the session last authenticated: its newest counting proof's time. */
        public CarbonImmutable $authenticatedAt,

        /** The session's authentication method reference values, possibly none. */
        public array $methods,
    ) {}
}
