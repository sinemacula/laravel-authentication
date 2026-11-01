<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Tenant access contract: may this principal act in this tenant?
 *
 * The tenant a session acts in (its active tenant) is the principal's own by
 * default, or none for a platform principal; an application whose principals
 * may act in other tenants (a tenant below their own, say) answers that here,
 * from its own tree and roles. The package sees only the tenant it is given and
 * never interprets the answer beyond yes or no; it asks at sign-in and at the
 * choice of principal for the tenant selected, on every switch for the
 * destination, and on refresh for the session's active tenant. A tenant it
 * refuses fails as `tenant_ineligible`. Listing the principals an identity may
 * use asks only `ApplicationAccess`: which tenant a listed principal acts in is
 * not known until a selection names it, so this contract is asked when the
 * principal is selected or chosen, with that selection.
 *
 * `null` asks whether the principal may act in no tenant. The default
 * (`OwnTenantOnly`) lets a principal act only in its own tenant, and a platform
 * principal only in none. The package asks it inside
 * `WriteConnection::during()` for the principal and the tenant, as
 * `ApplicationAccess` is asked.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantAccess
{
    /**
     * Whether the principal may act in the tenant, or in none for `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return bool
     */
    public function mayActIn(Principal $principal, ?Tenant $tenant): bool;
}
