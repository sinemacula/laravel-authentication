<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * The package's auth manager for benchmarks that build their guards by hand: it
 * holds each one as resolved under its name, as the manager does for a guard a
 * request resolved, so the listeners that look a resolved guard up
 * (`RecordSessionUsage`) take the path a request takes.
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
