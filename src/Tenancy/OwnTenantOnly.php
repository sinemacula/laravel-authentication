<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * The default tenant access: a principal may act only in its own tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OwnTenantOnly implements TenantAccess
{
    /**
     * Whether the tenant is the principal's own, or both are none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return bool
     *
     * @throws \LogicException
     */
    #[\Override]
    public function mayActIn(Principal $principal, ?Tenant $tenant): bool
    {
        try {
            $own = $principal->getTenant();
        } catch (TenantUnavailableException) {
            return false;
        }

        if ($own === null || $tenant === null) {
            return $own === null && $tenant === null;
        }

        return $own::class === $tenant::class && IdentifierCoercion::matches($own->getTenantIdentifier(), $tenant->getTenantIdentifier());
    }
}
