<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Whose external evidence the evidence policy judges, for which application,
 * connection and tenant, and when.
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
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
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

        /** The tenant whose requirement the evidence is judged against; `null` for the identity level and for its acceptance. */
        public ?Tenant $tenant = null,
    ) {}
}
