<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use Carbon\Carbon;

/**
 * Provides default Device contract method implementations sourced
 * from configurable Eloquent model attribute names.
 *
 * Models using this trait may override the protected attribute-name
 * methods to map to non-default column names.
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
     * Return the last login Carbon timestamp, or null when absent.
     *
     * @return ?\Carbon\Carbon
     */
    public function getLastLoggedIn(): ?Carbon
    {
        $value = $this->getAttribute($this->getLastLoggedInName());

        return $value instanceof Carbon ? $value : null;
    }

    /**
     * Return the last MFA verification Carbon timestamp, or null when absent.
     *
     * @return ?\Carbon\Carbon
     */
    public function getLastMfaVerification(): ?Carbon
    {
        $value = $this->getAttribute($this->getLastMfaVerificationName());

        return $value instanceof Carbon ? $value : null;
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
     * Return the hashed refresh key attribute cast to string.
     *
     * @return string
     */
    public function getRefreshKey(): string
    {
        return (string) $this->getAttribute($this->getRefreshKeyName());
    }

    /**
     * Column name holding the device identifier. Override in the consuming model to remap.
     *
     * @return string
     */
    protected function getDeviceIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Column name holding the last-login timestamp. Override in the consuming model to remap.
     *
     * @return string
     */
    protected function getLastLoggedInName(): string
    {
        return 'last_logged_in_at';
    }

    /**
     * Column name holding the last MFA verification timestamp. Override in the consuming model to remap.
     *
     * @return string
     */
    protected function getLastMfaVerificationName(): string
    {
        return 'last_mfa_verified_at';
    }

    /**
     * Column name holding the operating system string. Override in the consuming model to remap.
     *
     * @return string
     */
    protected function getOperatingSystemName(): string
    {
        return 'os';
    }

    /**
     * Column name holding the hashed refresh key. Override in the consuming model to remap.
     *
     * @return string
     */
    protected function getRefreshKeyName(): string
    {
        return 'refresh_key';
    }
}
