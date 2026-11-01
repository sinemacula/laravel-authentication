<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Applications;

use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * The package's default application access: any principal may use any
 * application. Bind another `ApplicationAccess` to keep some principals out of
 * an application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AdmitAnyPrincipal implements ApplicationAccess
{
    /**
     * Let the principal use the application.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    #[\Override]
    public function mayUse(string $application, Principal $principal): bool
    {
        return true;
    }
}
