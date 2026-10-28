<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Eloquent device origin contract.
 *
 * The column-name accessors of an Eloquent device for what its session started
 * with: the guard, the sign-in method and the type of identifier it used, the
 * name and platform the client gave, and the IP address and user agent it came
 * from. Part of `EloquentDevice`, so a custom device model implements it by
 * implementing that contract; the session service writes these columns when it
 * creates or continues a device.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EloquentDeviceOrigin
{
    /**
     * Column name holding the guard whose session the device holds.
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
