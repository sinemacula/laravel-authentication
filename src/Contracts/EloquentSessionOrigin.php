<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * The column-name accessors of an Eloquent session for what it started with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EloquentSessionOrigin
{
    /**
     * Column name holding the guard the session belongs to.
     *
     * @return string
     */
    public function getGuardName(): string;

    /**
     * Column name holding the sign-in method that started the session.
     *
     * @return string
     */
    public function getSignInMethodName(): string;

    /**
     * Column name holding the type of identifier the sign-in that started the
     * session used.
     *
     * @return string
     */
    public function getSignInIdentifierTypeName(): string;

    /**
     * Column name holding the name the client gave itself.
     *
     * @return string
     */
    public function getClientNameName(): string;

    /**
     * Column name holding the platform the client reported.
     *
     * @return string
     */
    public function getPlatformName(): string;

    /**
     * Column name holding the IP address the session was created from.
     *
     * @return string
     */
    public function getCreatedIpName(): string;

    /**
     * Column name holding the user agent the session was created with.
     *
     * @return string
     */
    public function getCreatedUserAgentName(): string;
}
