<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

/**
 * The `ActsAsSession` accessors for what a session started with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsSessionOrigin
{
    /**
     * Return the guard the session belongs to, or `null` when none was recorded
     * or the column is not loaded.
     *
     * @return ?string
     */
    public function getGuard(): ?string
    {
        return $this->toSessionString($this->optionalSessionAttribute($this->getGuardName()));
    }

    /**
     * Column name holding the guard the session belongs to.
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
        return $this->toSessionString($this->optionalSessionAttribute($this->getSignInMethodName()));
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
     * or `null` when it used none or none was recorded.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getSignInIdentifierType(): ?string
    {
        return $this->toSessionString($this->loadedSessionAttribute($this->getSignInIdentifierTypeName(), 'getSignInIdentifierType'));
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
