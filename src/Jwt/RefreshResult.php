<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Immutable token pair returned by a refresh exchange.
 *
 * The old refresh token is burned server-side during the exchange, so consumers
 * must replace their stored credential with the value in `$refreshToken`
 * immediately - the previous value will no longer authenticate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RefreshResult
{
    /**
     * Constructor.
     *
     * @param  string  $accessToken
     * @param  string  $refreshToken
     */
    public function __construct(

        /** Newly issued access token returned to the client. */
        #[\SensitiveParameter] public readonly string $accessToken,

        /** Newly issued refresh token that rotates the device's stored digest. */
        #[\SensitiveParameter] public readonly string $refreshToken,
    ) {}
}
