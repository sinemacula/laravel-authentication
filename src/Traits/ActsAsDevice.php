<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use Carbon\CarbonInterface;

/**
 * Provides default Device contract method implementations sourced
 * from configurable Eloquent model attribute names.
 *
 * Models using this trait may override the protected attribute-name
 * methods to map to non-default column names. All timestamp
 * accessors narrow to `CarbonInterface` rather than the concrete
 * `Carbon` class so consumer apps that configure Eloquent to cast
 * dates as `CarbonImmutable` (via `Date::use(...)`) are not silently
 * broken.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
trait ActsAsDevice
{
    /**
     * Return the device's stable identifier from the configured attribute.
     *
     * @return mixed
     */
    public function getDeviceIdentifier(): mixed
    {
        return $this->getAttribute($this->getDeviceIdentifierName());
    }

    /**
     * Return the last login timestamp, or null when absent.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastLoggedIn(): ?CarbonInterface
    {
        $value = $this->getAttribute($this->getLastLoggedInName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Return the last MFA verification timestamp, or null when absent.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastMfaVerification(): ?CarbonInterface
    {
        $value = $this->getAttribute($this->getLastMfaVerificationName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Return the operating system attribute cast to string.
     *
     * @return string
     */
    public function getOperatingSystem(): string
    {
        return (string) $this->getAttribute($this->getOperatingSystemName());
    }

    /**
     * Return the hashed refresh key attribute, or null when the
     * device has no refresh credential issued (newly registered,
     * revoked, or cleared).
     *
     * @return ?string
     */
    public function getRefreshKey(): ?string
    {
        $value = $this->getAttribute($this->getRefreshKeyName());

        if ($value === null) {
            return null;
        }

        return (string) $value;
    }

    /**
     * Return the revocation timestamp, or null when the device is
     * not revoked.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getRevokedAt(): ?CarbonInterface
    {
        $value = $this->getAttribute($this->getRevokedAtName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Column name holding the device identifier. Override in the
     * consuming model to remap. Public so listeners and the refresh
     * exchange can resolve the correct column without reflection.
     *
     * @return string
     */
    public function getDeviceIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Column name holding the last-login timestamp. Override in the
     * consuming model to remap. Public so the
     * `UpdateDeviceTimestamp` listener can honour the override when
     * writing the atomic throttle update.
     *
     * @return string
     */
    public function getLastLoggedInName(): string
    {
        return 'last_logged_in_at';
    }

    /**
     * Column name holding the last MFA verification timestamp. Override in the consuming model to remap.
     *
     * @return string
     */
    public function getLastMfaVerificationName(): string
    {
        return 'last_mfa_verified_at';
    }

    /**
     * Column name holding the operating system string. Override in the consuming model to remap.
     *
     * @return string
     */
    public function getOperatingSystemName(): string
    {
        return 'os';
    }

    /**
     * Column name holding the hashed refresh key. Override in the
     * consuming model to remap. Public so the refresh-token exchange
     * can compose its atomic CAS update against the correct column.
     *
     * @return string
     */
    public function getRefreshKeyName(): string
    {
        return 'refresh_key';
    }

    /**
     * Column name holding the revocation timestamp. Override in the
     * consuming model to remap. Public so the refresh-token exchange
     * can clear / set the column on the device row.
     *
     * @return string
     */
    public function getRevokedAtName(): string
    {
        return 'revoked_at';
    }
}
