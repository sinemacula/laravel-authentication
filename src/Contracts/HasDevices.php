<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Database\Eloquent\Builder;

/**
 * Identity capability contract: owns devices.
 *
 * Implementing identities expose a `devices()` Eloquent relation
 * builder so guards can resolve a device record from a hint.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
interface HasDevices
{
    /** Eloquent relation builder for the identity's devices. */
    public function devices(): Builder;
}
