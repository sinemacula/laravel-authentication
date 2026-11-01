<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;

/**
 * The default tenant authentication policy: no tenant requires a further factor
 * or a connection, and the answer has no version.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequireNothingOfTenants implements TenantAuthenticationPolicy
{
    /**
     * Require nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     */
    #[\Override]
    public function requirementFor(TenantPolicyContext $context): TenantRequirement
    {
        return new TenantRequirement;
    }
}
