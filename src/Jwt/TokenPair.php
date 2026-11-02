<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Immutable token pair: the first pair of a session the session service
 * started, or the pair a refresh or a switch rotated in.
 *
 * Either way it replaces any refresh token the client held for the session, so
 * consumers must store the value in `$refreshToken` immediately. After a
 * refresh the replaced token is honoured only for a short grace window (a retry
 * gets the current credential again); presented after it, it is treated as a
 * replay and revokes the session. A sign-in always starts a new session, and
 * one that proved the client's previous session revokes it, so that session's
 * refresh tokens are refused as revoked from then on.
 *
 * Both tokens are `Secret`s: reveal them only into the response that hands them
 * to the client, such as with `SecretResponse::json()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TokenPair
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $accessToken
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $refreshToken
     */
    public function __construct(

        /** Newly issued access token returned to the client. */
        public Secret $accessToken,

        /** Newly issued refresh token carrying the session's current rotation id. */
        public Secret $refreshToken,
    ) {}
}
