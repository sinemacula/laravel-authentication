<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Runtime\GuardContext;

/**
 * A guard that runs its flows on a `GuardContext`: the package's own guards,
 * and any guard built on `AbstractGuard`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface HasGuardContext
{
    /**
     * Return the context the guard's flows run with, the one its setters
     * rebind.
     *
     * @return \SineMacula\Laravel\Authentication\Runtime\GuardContext
     */
    public function context(): GuardContext;
}
