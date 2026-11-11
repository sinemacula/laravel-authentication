<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Auth manager that holds hand-built benchmark guards as resolved, so listeners
 * that look a resolved guard up take a request's path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchAuthManager extends AuthManager
{
    /**
     * Hold the guard as resolved under its name, in place of any held before.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    public function hold(AbstractGuard $guard): AbstractGuard
    {
        return $this->guards[$guard->getName()] = $guard;
    }
}
