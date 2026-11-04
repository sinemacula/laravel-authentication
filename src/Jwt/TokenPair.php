<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Http\RefreshCookie;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Immutable token pair: the first pair of a session the session service
 * started, or the pair a refresh or a switch rotated in.
 *
 * Either way it replaces any refresh token the client held for the session, so
 * consumers must store it immediately. After a refresh the replaced token is
 * honoured only for a short grace window (a retry gets the current credential
 * again); presented after it, it is treated as a replay and revokes the
 * session. A sign-in always starts a new session, and one that proved the
 * client's previous session revokes it, so that session's refresh tokens are
 * refused as revoked from then on.
 *
 * The refresh token travels as the application's transport says: a body
 * application's pair carries it in `$refreshToken`, and a cookie application's
 * carries only `$refreshCookie`, the cookie that sets it in the browser, so the
 * plain token never reaches the application's code or a response body. Every
 * token is a `Secret`: reveal it only into the response that hands it to the
 * client, such as with `SecretResponse::json()`, and attach the cookie with
 * `RefreshCookie::attachTo()`.
 *
 * The pair says when its access token expires, as the token's own `exp` does:
 * `$expiresAt`, and `$expiresIn`, its lifetime in seconds, for the `expires_in`
 * of an RFC 6749 section 5.1 response, so the client need not decode the token
 * to know when to refresh.
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
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  int  $expiresIn
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $refreshToken
     * @param  ?\SineMacula\Laravel\Authentication\Http\RefreshCookie  $refreshCookie
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Newly issued access token returned to the client. */
        public Secret $accessToken,

        /** When that access token expires: its `exp`. */
        public CarbonImmutable $expiresAt,

        /** The access token's lifetime in seconds (`exp` minus `iat`), as RFC 6749 section 5.1's `expires_in`. */
        public int $expiresIn,

        /** Newly issued refresh token carrying the session's current rotation id, for a body application. */
        public ?Secret $refreshToken,

        /** The cookie that carries that refresh token, for a cookie application. */
        public ?RefreshCookie $refreshCookie = null,
    ) {
        if ($expiresIn < 1) {
            throw new \InvalidArgumentException('A token pair\'s access token lives at least one second.');
        }

        if (($refreshToken === null) === ($refreshCookie === null)) {
            throw new \InvalidArgumentException('A token pair carries its refresh token either in the body or in a cookie, never both or neither.');
        }
    }
}
