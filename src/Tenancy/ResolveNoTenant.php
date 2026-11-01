<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * The package's default tenant resolver: no identifier names a tenant. The
 * package reads the principal's own tenant from the principal, so this is only
 * reached for another tenant, which is refused until the application binds a
 * resolver of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResolveNoTenant implements TenantResolver
{
    /**
     * Resolve no tenant.
     *
     * @param  string  $tenantId
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function resolve(string $tenantId): ?Tenant
    {
        return null;
    }
}
