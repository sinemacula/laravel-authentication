<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Explicit persistence boundary for refreshable Eloquent-backed devices.
 *
 * Extends the generic `Device` read surface with the relation and the
 * column-name accessors behind each persisted device attribute, which the
 * package's refresh rotation and last-seen persistence paths rely on.
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
     * Column name holding the device identifier.
     *
     * @return string
     */
    public function getDeviceIdentifierName(): string;

    /**
     * Column name holding the persisted last-logged-in timestamp.
     *
     * @return string
     */
    public function getLastLoggedInName(): string;

    /**
     * Column name holding the persisted last MFA verification timestamp.
     *
     * @return string
     */
    public function getLastMfaVerificationName(): string;

    /**
     * Column name holding the persisted operating system string.
     *
     * @return string
     */
    public function getOperatingSystemName(): string;

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
