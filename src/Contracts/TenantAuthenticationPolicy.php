<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;

/**
 * Tenant authentication policy contract.
 *
 * Asked, for a session that is to act or keeps acting in a tenant, what the
 * tenant requires of its authentication: a further factor, the connections it
 * must have been established through, and the version of that answer. The
 * package asks it at sign-in, at a choice of principal, at activation, at every
 * refresh and when the `me` route binding reads a refresh credential, never on
 * a bearer request; a switch asks it for the destination. The default,
 * `RequireNothingOfTenants`, requires nothing.
 *
 * It is asked inside `WriteConnection::during()` for the tenant: read the
 * policy's own state from the write connection every time, so a lagging replica
 * never answers with a policy that has just changed. Change the version
 * whenever anything the answer depends on changes, the exemptions included, and
 * call `Auth::sessions()->tenantPolicyChanged($tenant)` when the policy
 * changes, so sessions that no longer meet it end.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantAuthenticationPolicy
{
    /**
     * What the tenant requires of a session acting in it.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     */
    public function requirementFor(TenantPolicyContext $context): TenantRequirement;
}
