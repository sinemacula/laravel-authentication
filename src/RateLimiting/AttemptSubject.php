<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * Who is attempting a flow of a guard, by identifier, IP address and, once
 * known, account.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttemptSubject
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @param  ?string  $identifier
     * @param  ?string  $identifierType
     * @param  ?string  $ip
     * @param  ?string  $account
     */
    public function __construct(

        /** Guard whose limits apply. */
        public string $guard,

        /** Flow being attempted. */
        public AttemptFlow $flow,

        /** Identifier the attempt names, as given, or `null` when it names none. */
        public ?string $identifier,

        /** Type of the identifier (for example `email`), which names its normaliser. */
        public ?string $identifierType,

        /** IP address the attempt came from, or `null` when unknown. */
        public ?string $ip,

        /** Account whose secret the attempt checks, or `null` when none is known yet. */
        public ?string $account = null,
    ) {}
}
