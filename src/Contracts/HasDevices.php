<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Database\Eloquent\Builder;

/**
 * Identity capability contract: owns devices.
 *
 * Implementing identities expose an Eloquent relation builder so bearer-token
 * resolution can look up an Eloquent-backed device record from a hint.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasDevices
{
    /**
     * Eloquent relation builder for the identity's devices.
     *
     * The guard calls it inside `WriteConnection::during()` for the identity,
     * so a query the relation runs while it is built reads the write
     * connection. The devices it returns must carry the revocation column:
     * `ActsAsDevice` throws for a device loaded without it.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function devices(): Builder;
}
