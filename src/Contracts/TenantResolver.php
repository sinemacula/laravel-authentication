<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Tenant resolver contract: the tenant an opaque identifier names.
 *
 * The package carries a tenant only as an opaque identifier, a string (a
 * session's active tenant, a selection at sign-in or on a switch), and never
 * sees node types or a hierarchy. It never asks the resolver for the
 * principal's own tenant, which it reads from the principal's `getTenant()`, so
 * the resolver is reached only for a tenant other than the principal's own: one
 * an application lets principals act in through `TenantAccess`.
 *
 * Return the tenant, or `null` when the identifier names none (or none the
 * application will act on). Read it from the write connection: the package asks
 * inside `WriteConnection::during()` for the principal, so a model read is
 * pinned, and a query-builder read pins itself with `WriteConnection::query()`.
 * A tenant that can be deactivated implements `CanBeActive`, and the package
 * checks it as it checks the principal's own. The default (`ResolveNoTenant`)
 * resolves nothing, so an application that lets principals act in other tenants
 * binds a resolver too, or every such tenant is refused.
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
