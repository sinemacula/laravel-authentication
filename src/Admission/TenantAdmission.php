<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * The tenant a principal is to act in (a session's active tenant): the one a
 * selection asks for, or the one a session records, resolved, held to
 * `TenantAccess` and checked active.
 *
 * The principal's own tenant is read from its `getTenant()` and never from the
 * `TenantResolver`, so with the defaults no resolver is asked; any other tenant
 * is resolved by its identifier, and a tenant the resolver returns under
 * another identifier is not taken for it. Every read, and both contracts, run
 * inside `WriteConnection::during()` for the principal (and for the tenant when
 * there is one), with the bindings in effect when they are asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantAdmission
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The tenant the principal is to act in for the selection (`null` for
     * none), or why not: `tenant_ineligible` when a named tenant cannot be
     * resolved or `TenantAccess` refuses it, and `tenant_inactive` when it is
     * inactive or when the principal's own tenant cannot be loaded. Activity is
     * checked only for a tenant the principal may act in, so the answer says
     * nothing about any other.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $selection
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    public static function select(Principal $principal, TenantSelection $selection): FailureReason|Tenant|null
    {
        $own = self::own($principal);

        if ($own instanceof FailureReason) {
            return $own;
        }

        $tenantId = $selection->tenantId();
        $tenant   = match (true) {
            $selection->isPrincipalDefault() => $own,
            $tenantId === null               => null,
            default                          => self::named($principal, $own, $tenantId) ?? FailureReason::TENANT_INELIGIBLE,
        };

        return $tenant instanceof FailureReason ? $tenant : self::admitted($principal, $tenant, true);
    }

    /**
     * The active tenant a session records (`null` for none), for the principal
     * it acts as, or why not: `tenant_inactive` when the tenant cannot be
     * resolved, is inactive, or the principal's own tenant cannot be loaded;
     * with `$checkAccess` (a refresh, a switch), `tenant_ineligible` when
     * `TenantAccess` no longer lets the principal act in it. A bearer request
     * does not ask the access contract.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $tenantId
     * @param  bool  $checkAccess
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    public static function recorded(Principal $principal, ?string $tenantId, bool $checkAccess): FailureReason|Tenant|null
    {
        $tenant = null;

        if ($tenantId !== null) {

            $own = self::own($principal);

            if ($own instanceof FailureReason) {
                return $own;
            }

            $tenant = self::named($principal, $own, $tenantId) ?? FailureReason::TENANT_INACTIVE;
        }

        return $tenant instanceof FailureReason ? $tenant : self::admitted($principal, $tenant, $checkAccess);
    }

    /**
     * The tenant the identifier names, with no access or activity check: the
     * principal's own when its identifier matches, otherwise the resolver's
     * answer, asked on the write connection for the principal, when that answer
     * has the identifier asked for, else `null`. For a trusted bind, which
     * binds the tenant a session records without checking it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $own
     * @param  string  $tenantId
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function named(Principal $principal, ?Tenant $own, string $tenantId): ?Tenant
    {
        if ($own !== null && IdentifierCoercion::matches($own->getTenantIdentifier(), $tenantId)) {
            return $own;
        }

        $resolver = Container::getInstance()->make(TenantResolver::class);
        $resolved = WriteConnection::during($principal, static fn (): ?Tenant => $resolver->resolve($tenantId));

        return $resolved !== null && IdentifierCoercion::matches($resolved->getTenantIdentifier(), $tenantId) ? $resolved : null;
    }

    /**
     * The principal's own tenant, read on the write connection, `null` for a
     * platform principal, or `tenant_inactive` when it opts into activation and
     * cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \LogicException
     */
    private static function own(Principal $principal): FailureReason|Tenant|null
    {
        try {
            return WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());
        } catch (TenantUnavailableException) {
            return FailureReason::TENANT_INACTIVE;
        }
    }

    /**
     * The tenant once the principal may act in it (asked only with
     * `$checkAccess`, `tenant_ineligible` otherwise) and it is active
     * (`tenant_inactive` otherwise); no tenant is never inactive.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  bool  $checkAccess
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function admitted(Principal $principal, ?Tenant $tenant, bool $checkAccess): FailureReason|Tenant|null
    {
        if ($checkAccess && !self::mayActIn($principal, $tenant)) {
            return FailureReason::TENANT_INELIGIBLE;
        }

        return $tenant === null || ActivationPolicy::isActive($tenant) ? $tenant : FailureReason::TENANT_INACTIVE;
    }

    /**
     * Whether `TenantAccess` lets the principal act in the tenant, asked on the
     * write connection for the principal and the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function mayActIn(Principal $principal, ?Tenant $tenant): bool
    {
        $access = Container::getInstance()->make(TenantAccess::class);
        $ask    = static fn (): bool => $access->mayActIn($principal, $tenant);

        return WriteConnection::during($principal, static fn (): bool => $tenant === null ? $ask() : WriteConnection::during($tenant, $ask));
    }
}
