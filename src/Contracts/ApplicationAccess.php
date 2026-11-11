<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Decides whether a principal may use an application.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ApplicationAccess
{
    /**
     * Whether the principal may use the application (its guard's name).
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    public function mayUse(string $application, Principal $principal): bool;
}
