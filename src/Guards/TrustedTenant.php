<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;

/**
 * Finds the active tenant a trusted bind gives a principal, unchecked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TrustedTenant
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The tenant the session records for the principal, or the principal's own
     * without a session, `null` for none, or why it cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    public static function of(Principal $principal, ?Session $session): Tenant|TenantUnavailableException|null
    {
        return $session === null
            ? self::own($principal)
            : self::recorded($principal, WriteConnection::during($session, static fn (): ?string => $session->getTenantId()));
    }

    /**
     * The principal's own tenant, `null` for none, or why it cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null
     *
     * @throws \LogicException
     */
    private static function own(Principal $principal): Tenant|TenantUnavailableException|null
    {
        try {
            return WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());
        } catch (TenantUnavailableException $exception) {
            return $exception;
        }
    }

    /**
     * The tenant a session records, `null` when it records none, or why it
     * cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function recorded(Principal $principal, ?string $tenantId): Tenant|TenantUnavailableException|null
    {
        if ($tenantId === null) {
            return null;
        }

        $own    = self::own($principal);
        $tenant = TenantAdmission::named($principal, $own instanceof Tenant ? $own : null, $tenantId);

        return $tenant ?? ($own instanceof TenantUnavailableException ? $own : self::unresolvable($tenantId));
    }

    /**
     * The reason a tenant a session records cannot be bound: it no longer
     * resolves.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    private static function unresolvable(string $tenantId): TenantUnavailableException
    {
        return new TenantUnavailableException(sprintf('The tenant %s the bound session records cannot be resolved.', $tenantId));
    }
}
