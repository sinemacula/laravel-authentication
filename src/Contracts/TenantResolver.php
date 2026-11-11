<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Resolves the tenant an opaque identifier names, for a tenant other than the
 * principal's own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantResolver
{
    /**
     * The tenant the identifier names, or `null`.
     *
     * @param  string  $tenantId
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    public function resolve(string $tenantId): ?Tenant;
}
