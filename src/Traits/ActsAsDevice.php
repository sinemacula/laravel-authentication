<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use Carbon\CarbonInterface;

/**
 * Provides the default Eloquent-backed `Device` accessor and column-name
 * implementations sourced from conventional attribute names. Override the
 * public `*Name()` methods to remap columns while still satisfying the
 * explicit `EloquentDevice` persistence boundary. Timestamp accessors narrow to
 * `CarbonInterface` so `CarbonImmutable` consumers are not broken.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
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
     * Column name holding the device identifier. Public so listeners and the
     * refresh exchange can resolve the column without reflection.
     *
     * @return string
     */
    public function getDeviceIdentifierName(): string
    {
        return 'id';
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
     * Column name holding the last-login timestamp. Public so the
     * `UpdateDeviceTimestamp` listener honours the override.
     *
     * @return string
     */
    public function getLastLoggedInName(): string
    {
        return 'last_logged_in_at';
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
     * Column name holding the last MFA verification timestamp.
     *
     * @return string
     */
    public function getLastMfaVerificationName(): string
    {
        return 'last_mfa_verified_at';
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
     * Column name holding the operating system string.
     *
     * @return string
     */
    public function getOperatingSystemName(): string
    {
        return 'os';
    }

    /**
     * Return the hashed refresh key attribute, or null when no refresh
     * credential has been issued.
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
     * Column name holding the hashed refresh key. Public so the refresh-token
     * exchange can compose its atomic CAS update.
     *
     * @return string
     */
    public function getRefreshKeyName(): string
    {
        return 'refresh_key';
    }

    /**
     * Return the revocation timestamp, or null when the device is not revoked.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getRevokedAt(): ?CarbonInterface
    {
        $value = $this->getAttribute($this->getRevokedAtName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Column name holding the revocation timestamp. Public so the refresh-token
     * exchange can clear / set the column.
     *
     * @return string
     */
    public function getRevokedAtName(): string
    {
        return 'revoked_at';
    }
}
