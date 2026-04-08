<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Coerce identifier values returned by package contracts into JWT
 * claim strings.
 *
 * RFC 7519 §4.1.2 requires `sub` (and by extension `pid`/`did`/`jti`)
 * to be a `StringOrURI`, but the contract getters return `mixed`.
 * Centralised so the JWT service and the fail-closed pid-hint
 * comparison in `JwtGuard` cannot drift apart.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class IdentifierCoercion
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Coerce an identifier to a string for embedding in a JWT claim.
     * Returns `null` for `null` and for non-scalar, non-Stringable input.
     *
     * @param  mixed  $identifier
     * @return string|null
     */
    public static function stringify(mixed $identifier): ?string
    {
        return match (true) {
            $identifier === null   => null,
            is_string($identifier) => $identifier,
            is_int($identifier),
            is_float($identifier),
            is_bool($identifier),
            $identifier instanceof \Stringable => (string) $identifier,
            default                            => null,
        };
    }
}
