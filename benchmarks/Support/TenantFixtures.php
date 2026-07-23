<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;

/**
 * Shared tenant-aware fixture seeding for the benchmark harnesses.
 *
 * Find-or-create helpers keyed by name so repeated harness boots reuse the same
 * tenant and principal rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TenantFixtures
{
    /**
     * Find or create the named benchmark tenant.
     *
     * @param  string  $name
     * @param  string  $type
     * @return \Tests\Integration\Fixtures\TenantAware3dTenant
     */
    public static function seedTenant(string $name, string $type): TenantAware3dTenant
    {
        $tenant = TenantAware3dTenant::query()->where('name', $name)->first();

        if ($tenant instanceof TenantAware3dTenant) {
            return $tenant;
        }

        $tenant       = new TenantAware3dTenant;
        $tenant->name = $name;
        $tenant->type = $type;
        $tenant->save();

        return $tenant;
    }

    /**
     * Find or create the named principal bound to the identity and tenant.
     *
     * @param  \Tests\Integration\Fixtures\TenantAware3dIdentity  $identity
     * @param  \Tests\Integration\Fixtures\TenantAware3dTenant  $tenant
     * @param  string  $name
     * @return \Tests\Integration\Fixtures\TenantAware3dPrincipal
     */
    public static function seedTenantPrincipal(TenantAware3dIdentity $identity, TenantAware3dTenant $tenant, string $name): TenantAware3dPrincipal
    {
        $principal = TenantAware3dPrincipal::query()
            ->where('identity_id', $identity->getKey())
            ->where('name', $name)
            ->first();

        if ($principal instanceof TenantAware3dPrincipal) {
            return $principal;
        }

        /** @var int $identityKey */
        $identityKey = $identity->getKey();

        /** @var int $tenantKey */
        $tenantKey = $tenant->getKey();

        $principal              = new TenantAware3dPrincipal;
        $principal->identity_id = $identityKey;
        $principal->tenant_id   = $tenantKey;
        $principal->name        = $name;
        $principal->is_active   = true;
        $principal->save();

        return $principal;
    }
}
