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
     * Return the tenant the principal acts within, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    public function getTenant(): ?Tenant;

    /**
     * Return whether the principal is currently active and may authenticate.
     *
     * @return bool
     */
    public function isActive(): bool;
}
