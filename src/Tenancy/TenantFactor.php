<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * A tenant's further-factor requirement with the tenant whose it is, as the
 * requirement judge takes it, so the evidence policy is told whose requirement
 * it judges and one tenant's trust in a connection never meets another's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantFactor
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     */
    public function __construct(

        /** The tenant whose requirement it is. */
        public Tenant $tenant,

        /** What the tenant requires of the session's authentication. */
        public Requirement $requirement,
    ) {}
}
