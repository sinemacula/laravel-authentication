<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Principal contract.
 *
 * Describes the *acting* entity for an authenticated request, which may differ
 * from the underlying identity (in the 3D model) or be the identity itself (in
 * the 2D model).
 *
 * Activation is not part of this contract: a principal that can be deactivated
 * also implements `CanBeActive`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Principal
{
    /**
     * Return the principal's stable identifier (typically the model key).
     *
     * @return mixed
     */
    public function getPrincipalIdentifier(): mixed;

    /**
     * Return the identity that owns this principal (in 2D mode this is the
     * principal itself).
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    public function getIdentity(): Identity;

    /**
     * Return the tenant the principal acts within, if any. The activity check
     * runs it with reads on this principal's connection pinned to the write
     * connection; a lookup on any other connection must pin itself (see
     * `Database\WriteConnection`).
     *
     * Return `null` only for a principal that acts within no tenant. When the
     * principal names a tenant that cannot be loaded (deleted, soft-deleted, or
     * hidden by a scope), throw `TenantUnavailableException`, which the
     * activity check treats as an inactive tenant; `null` would let the
     * principal authenticate as if it had no tenant.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function getTenant(): ?Tenant;
}
