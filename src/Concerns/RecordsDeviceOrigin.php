<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

/**
 * The `ActsAsDevice` accessors for what a device's session started with: the
 * guard, the sign-in method and the type of identifier it used, the name and
 * platform the client gave, and the IP address and user agent it came from.
 * These are informational, so a value that was not loaded reads as `null`.
 * Override the `*Name()` methods to remap columns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsDeviceOrigin
{
    /**
     * Return the guard whose session the device holds, or `null` when none was
     * recorded or the column is not loaded.
     *
     * @return ?string
     */
    public function getGuard(): ?string
    {
        return $this->toDeviceString($this->optionalDeviceAttribute($this->getGuardName()));
    }

    /**
     * Column name holding the guard whose session the device holds.
     *
     * @return string
     */
    public function getGuardName(): string
    {
        return 'guard';
    }

    /**
     * Return the sign-in method that started the session, or `null` when none
     * was recorded or the column is not loaded.
     *
     * @return ?string
     */
    public function getSignInMethod(): ?string
    {
        return $this->toDeviceString($this->optionalDeviceAttribute($this->getSignInMethodName()));
    }

    /**
     * Column name holding the sign-in method that started the session.
     *
     * @return string
     */
    public function getSignInMethodName(): string
    {
        return 'sign_in_method';
    }

    /**
     * Return the type of identifier the sign-in that started the session used,
     * or `null` when it used none, none was recorded, or the column is not
     * loaded.
     *
     * @return ?string
     */
    public function getSignInIdentifierType(): ?string
    {
        return $this->toDeviceString($this->optionalDeviceAttribute($this->getSignInIdentifierTypeName()));
    }

    /**
     * Column name holding the type of identifier the sign-in that started the
     * session used.
     *
     * @return string
     */
    public function getSignInIdentifierTypeName(): string
    {
        return 'sign_in_identifier_type';
    }

    /**
     * Column name holding the name the client gave itself.
     *
     * @return string
     */
    public function getClientNameName(): string
    {
        return 'client_name';
    }

    /**
     * Column name holding the platform the client reported.
     *
     * @return string
     */
    public function getPlatformName(): string
    {
        return 'platform';
    }

    /**
     * Column name holding the IP address the session was created from.
     *
     * @return string
     */
    public function getCreatedIpName(): string
    {
        return 'created_ip';
    }

    /**
     * Column name holding the user agent the session was created with.
     *
     * @return string
     */
    public function getCreatedUserAgentName(): string
    {
        return 'created_user_agent';
    }
}
