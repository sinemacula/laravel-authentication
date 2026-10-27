<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Immutable token pair returned by a refresh exchange.
 *
 * The presented refresh token is replaced during the exchange, so consumers
 * must store the value in `$refreshToken` immediately. The replaced token is
 * honoured only for a short grace window (a retry gets the current credential
 * again); presented after it, it is treated as a replay and revokes the device.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshResult
{
    /**
     * Constructor.
     *
     * @param  string  $accessToken
     * @param  string  $refreshToken
     */
    public function __construct(

        /** Newly issued access token returned to the client. */
        #[\SensitiveParameter] public string $accessToken,

        /** Newly issued refresh token carrying the device's current rotation id. */
        #[\SensitiveParameter] public string $refreshToken,
    ) {}
}
