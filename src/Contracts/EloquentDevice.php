<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Explicit persistence boundary for refreshable Eloquent-backed devices.
 *
 * Extends the generic `Device` read surface with the relation and column-name
 * accessors the package's refresh rotation and last-seen persistence paths
 * require.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EloquentDevice extends Device
{
    /**
     * Polymorphic relation to the owning authenticatable identity.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo;

    /**
     * Column name holding the persisted last-logged-in timestamp.
     *
     * @return string
     */
    public function getLastLoggedInName(): string;

    /**
     * Column name holding the persisted hashed refresh-key digest.
     *
     * @return string
     */
    public function getRefreshKeyName(): string;

    /**
     * Column name holding the persisted revocation timestamp.
     *
     * @return string
     */
    public function getRevokedAtName(): string;
}
