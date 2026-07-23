<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;

/**
 * Device contract.
 *
 * Describes the generic read-only device surface carried through token
 * issuance, guard state, and package events. Persistence-capable refresh
 * rotation and last-seen writes require the narrower `EloquentDevice` boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Device
{
    /**
     * Return the device's stable identifier (typically a UUID v7).
     *
     * @return mixed
     */
    public function getDeviceIdentifier(): mixed;

    /**
     * Return when the device was last successfully authenticated. Returns
     * `CarbonInterface` so consumer apps that configure `CarbonImmutable` casts
     * are not silently broken.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastLoggedIn(): ?CarbonInterface;

    /**
     * Return when the device's MFA factor was last verified.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastMfaVerification(): ?CarbonInterface;

    /**
     * Return the operating system string captured at registration.
     *
     * @return string
     */
    public function getOperatingSystem(): string;

    /**
     * Return the hashed refresh-key digest stored on the device row. NEVER the
     * plaintext rotation identifier - the refresh exchange verifies the
     * plaintext against this digest via `hash_equals()`. Returns `null` when no
     * refresh credential has been issued or after revocation cleared the
     * column.
     *
     * @return ?string
     */
    public function getRefreshKey(): ?string;

    /**
     * Return when the device was revoked, or `null`. A non-null value causes
     * the refresh exchange to reject refresh attempts with reason
     * `device_revoked`.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getRevokedAt(): ?CarbonInterface;
}
