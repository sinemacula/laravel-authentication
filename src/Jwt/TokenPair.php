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
