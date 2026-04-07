<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\Carbon;

/**
 * Device contract.
 *
 * Describes a refreshable device record bound to an authenticated
 * identity. Implementations are typically Eloquent models.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
interface Device
{
    /**
     * Return the device's stable identifier (typically the ULID primary key).
     *
     * @return mixed
     */
    public function getDeviceIdentifier(): mixed;

    /**
     * Return when the device was last successfully authenticated.
     *
     * @return ?\Carbon\Carbon
     */
    public function getLastLoggedIn(): ?Carbon;

    /**
     * Return when the device's MFA factor was last verified.
     *
     * @return ?\Carbon\Carbon
     */
    public function getLastMfaVerification(): ?Carbon;

    /**
     * Return the operating system string captured at registration.
     *
     * @return string
     */
    public function getOperatingSystem(): string;

    /**
     * Return the hashed refresh-key used for refresh-credential lookup.
     *
     * The returned value is the opaque digest stored on the device row
     * — typically a SHA-256 hex string produced via `hashRotationId()`.
     * It is NEVER the plaintext rotation identifier. The guard
     * verifies the plaintext from the refresh token against this
     * digest via `hash_equals()` (constant-time).
     *
     * @return string
     */
    public function getRefreshKey(): string;
}
