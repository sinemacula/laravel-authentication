<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * The default tenant resolver, which resolves no tenant.
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
