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
 * Resolves the tenant a principal is to act in, held to `TenantAccess` and
 * checked active.
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
     * none), or why not.
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
     * it acts as, or why not.
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
     * The tenant the identifier names, with no access or activity check.
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
     * The principal's own tenant, `null` for none, or `tenant_inactive` when it
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
     * The tenant once the principal may act in it and it is active, or why not.
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
     * write connection.
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
