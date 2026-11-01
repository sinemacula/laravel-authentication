<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;

/**
 * What a session's authentication amounts to when a token is issued for it: the
 * time of its latest authentication (`auth_time`) and the authentication method
 * references it used (`amr`).
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

        /** When the session last authenticated. */
        public CarbonImmutable $authenticatedAt,

        /** The authentication method references the session's authentication used. */
        public array $methods,
    ) {}
}
