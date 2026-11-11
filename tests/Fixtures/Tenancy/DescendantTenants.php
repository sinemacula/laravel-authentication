<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Integration\Fixtures\ActivatableTenant;

/**
 * Tenant access and resolver that let principals act in their own tenant and
 * those below it, counting every question.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DescendantTenants implements TenantAccess, TenantResolver
{
    /** @var int How many times the access was asked. */
    public int $asked = 0;

    /** @var int How many times a tenant was resolved. */
    public int $resolved = 0;

    /**
     * Constructor.
     *
     * @param  array<string, list<string>>  $below
     * @param  bool  $platformAnywhere
     */
    public function __construct(

        /** The identifiers of the tenants below each tenant, by that tenant's identifier. */
        private array $below = [],

        /** Whether a platform principal may act in any tenant. */
        private bool $platformAnywhere = false,
    ) {}

    /**
     * Whether the tenant is the principal's own, or one the tree lists below
     * it, or, for a platform principal, none or any when allowed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return bool
     */
    #[\Override]
    public function mayActIn(Principal $principal, ?Tenant $tenant): bool
    {
        $this->asked++;

        $own = IdentifierCoercion::stringify($principal->getTenant()?->getTenantIdentifier());
        $id  = IdentifierCoercion::stringify($tenant?->getTenantIdentifier());

        return $own === null
            ? $id   === null || $this->platformAnywhere
            : $own  === $id  || in_array($id, $this->below[$own] ?? [], true);
    }

    /**
     * The activatable tenant with the key, read on the write connection.
     *
     * @param  string  $tenantId
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function resolve(string $tenantId): ?Tenant
    {
        $this->resolved++;

        return WriteConnection::query(ActivatableTenant::query())->find($tenantId);
    }

    /**
     * List the descendant below the tenant in the tree.
     *
     * @param  int|string  $descendant
     * @param  int|string  $tenant
     * @return self
     */
    public function place(int|string $descendant, int|string $tenant): self
    {
        $this->below[(string) $tenant][] = (string) $descendant;

        return $this;
    }
}
