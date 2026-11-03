<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Whose external evidence the evidence policy judges, and when: the identity,
 * the application (the guard) the session is on, the connection (the configured
 * external provider) that asserted the evidence, and the time it is judged at.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EvidenceSubject
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  string  $connectionId
     * @param  \Carbon\CarbonImmutable  $now
     */
    public function __construct(

        /** The identity the evidence is about. */
        public Identity $identity,

        /** The application (the guard) the session is on. */
        public string $application,

        /** The connection that asserted the evidence. */
        public string $connectionId,

        /** The time the evidence is judged at. */
        public CarbonImmutable $now,
    ) {}
}
