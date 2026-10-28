<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Explicit persistence boundary for refreshable Eloquent-backed devices.
 *
 * Extends the generic `Device` read surface with the relations and the
 * column-name accessors behind each persisted device attribute, which the
 * package's session creation, refresh rotation, revocation, and last-use
 * persistence paths rely on. The columns that record what the session started
 * with are named through `EloquentDeviceOrigin`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EloquentDevice extends Device, EloquentDeviceOrigin
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
     * Polymorphic relation to the principal the device's session acts as.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function principal(): MorphTo;

    /**
     * Column name holding when the device was last used.
     *
     * @return string
     */
    public function getLastUsedAtName(): string;

    /**
     * Column name holding the IP address the device was last used from.
     *
     * @return string
     */
    public function getLastUsedIpName(): string;

    /**
     * Column name holding the user agent the device was last used with.
     *
     * @return string
     */
    public function getLastUsedUserAgentName(): string;

    /**
     * Column name holding the digest of the current refresh rotation id.
     *
     * @return string
     */
    public function getRefreshKeyName(): string;

    /**
     * Column name holding the digest of the previous refresh rotation id.
     *
     * @return string
     */
    public function getPreviousRefreshKeyName(): string;

    /**
     * Column name holding when the current refresh rotation id replaced the
     * previous one.
     *
     * @return string
     */
    public function getRefreshRotatedAtName(): string;

    /**
     * Column name holding when the session started.
     *
     * @return string
     */
    public function getSignedInAtName(): string;

    /**
     * Column name holding when the session last switched its principal.
     *
     * @return string
     */
    public function getPrincipalSwitchedAtName(): string;

    /**
     * Column name holding the idle deadline.
     *
     * @return string
     */
    public function getIdleExpiresAtName(): string;

    /**
     * Column name holding the absolute deadline.
     *
     * @return string
     */
    public function getAbsoluteExpiresAtName(): string;

    /**
     * Column name holding the revocation timestamp.
     *
     * @return string
     */
    public function getRevokedAtName(): string;

    /**
     * Column name holding the revocation reason.
     *
     * @return string
     */
    public function getRevokedReasonName(): string;
}
