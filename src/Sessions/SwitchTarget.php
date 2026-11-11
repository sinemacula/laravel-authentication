<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Where a switch takes a session: another principal of the same identity, or
 * another active tenant.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SwitchTarget
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     */
    private function __construct(

        /** The principal to switch to; `null` keeps the one the session acts as. */
        public ?Principal $principal,

        /** The tenant to act in; `null` for the principal's default. */
        public ?TenantSelection $tenant,
    ) {}

    /**
     * Switch to the principal, in the tenant selected (its default when none
     * is).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     * @return self
     */
    public static function principal(Principal $principal, ?TenantSelection $tenant = null): self
    {
        return new self($principal, $tenant);
    }

    /**
     * Switch the session's active tenant, keeping the principal it acts as.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     * @return self
     */
    public static function tenant(TenantSelection $tenant): self
    {
        return new self(null, $tenant);
    }
}
