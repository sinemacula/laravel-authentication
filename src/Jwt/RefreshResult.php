<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Immutable result of a successful refresh-token exchange.
 *
 * Carries the newly issued access token and the *rotated* refresh
 * token. The old refresh token is burned on the server side during
 * the exchange (its stored hash is overwritten with the new one), so
 * consumers must replace their stored refresh credential with the
 * value in `$refreshToken` immediately — the previous value will no
 * longer authenticate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
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

        /** The newly issued short-lived access token (JWT). */
        #[\SensitiveParameter] public string $accessToken,

        /** The newly issued rotated refresh token (JWT). */
        #[\SensitiveParameter] public string $refreshToken,

    ) {}
}
