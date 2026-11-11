<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;

/**
 * Decides whether an identity, principal or tenant may authenticate; a model is
 * active unless it implements `CanBeActive` and reports otherwise.
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
     * Whether the subject may authenticate, read on the write connection.
     *
     * @param  object  $subject
     * @return bool
     */
    public static function isActive(object $subject): bool
    {
        return !$subject instanceof CanBeActive || WriteConnection::during($subject, static fn (): bool => $subject->isActive());
    }

    /**
     * Whether the tenant the principal acts within, if any, may authenticate.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    public static function isTenantActive(Principal $principal): bool
    {
        return self::activeTenant($principal) !== false;
    }

    /**
     * Return the principal's tenant when it may authenticate, `null` for none,
     * or `false` when it is inactive or cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return false|\SineMacula\Laravel\Authentication\Contracts\Tenant|null
     */
    public static function activeTenant(Principal $principal): false|Tenant|null
    {
        try {
            $tenant = WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());
        } catch (TenantUnavailableException) {
            return false;
        }

        return $tenant === null || self::isActive($tenant) ? $tenant : false;
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
