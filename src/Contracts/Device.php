<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;

/**
 * Device contract.
 *
 * Describes a refreshable device record bound to an authenticated
 * identity. Implementations are typically Eloquent models.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
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
     * Returns a `CarbonInterface` so consumer apps that configure
     * Eloquent to cast timestamps as `CarbonImmutable` (via
     * `Date::use(CarbonImmutable::class)`) are not silently broken.
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
     * Return the hashed refresh-key used for refresh-credential lookup.
     *
     * The returned value is the opaque digest stored on the device
     * row — typically a SHA-256 hex string produced via
     * `RefreshTokenHasher::hash()`. It is NEVER the plaintext
     * rotation identifier. The refresh exchange verifies the
     * plaintext from the refresh token against this digest via
     * `hash_equals()` (constant-time).
     *
     * Returns `null` when the device has no refresh credential
     * issued (e.g. immediately after device registration, or after
     * revocation cleared the column).
     *
     * @return ?string
     */
    public function getRefreshKey(): ?string;

    /**
     * Return when the device was revoked, or `null` if it has not
     * been revoked. A non-null value causes the refresh exchange
     * to reject any refresh attempt against this device with
     * reason `device_revoked`.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getRevokedAt(): ?CarbonInterface;
}
