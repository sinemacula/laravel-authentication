<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;

/**
 * The package's activation policy, shared by the credential, bearer-token and
 * refresh paths.
 *
 * Activation is an opt-in capability: a model is active unless it implements
 * `CanBeActive` and reports otherwise, so an ordinary model with no activation
 * column always authenticates. The identity, the principal, and the tenant the
 * principal acts within are each checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ActivationPolicy
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the subject (an identity, principal, or tenant) may authenticate.
     * Returns `true` for subjects that do not implement `CanBeActive`.
     *
     * @param  object  $subject
     * @return bool
     */
    public static function isActive(object $subject): bool
    {
        return !$subject instanceof CanBeActive || $subject->isActive();
    }

    /**
     * Whether the tenant the principal acts within, if any, may authenticate. A
     * principal with no tenant passes.
     *
     * The tenant is read with the principal's connection pinned to the write
     * connection, so a lazily loaded tenant relation cannot come from a replica
     * that has not yet seen a deactivation.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    public static function isTenantActive(Principal $principal): bool
    {
        $tenant = WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());

        return $tenant === null || self::isActive($tenant);
    }

    /**
     * Whether the principal and the tenant it acts within may both
     * authenticate.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    public static function isPrincipalActive(Principal $principal): bool
    {
        return self::isActive($principal) && self::isTenantActive($principal);
    }
}
