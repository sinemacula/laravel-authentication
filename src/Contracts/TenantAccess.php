<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Decides whether a principal may act in a tenant.
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
