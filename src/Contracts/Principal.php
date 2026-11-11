<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * The acting entity for an authenticated request: the identity itself, or one
 * it acts as.
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
     * Return the identity that owns this principal, itself in two-dimensional
     * mode.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    public function getIdentity(): Identity;

    /**
     * Return the tenant the principal acts within, if any; an activatable
     * tenant that cannot be loaded throws `TenantUnavailableException`.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     */
    public function getTenant(): ?Tenant;
}
