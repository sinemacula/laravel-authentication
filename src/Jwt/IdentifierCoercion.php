<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Coerce identifier values returned by package contracts into JWT claim
 * strings, and compare identifiers in that form.
 *
 * RFC 7519 §4.1.2 requires `sub` (and `pid`/`did`/`jti`) to be a `StringOrURI`,
 * but the contract getters return `mixed`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class IdentifierCoercion
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Coerce an identifier to a string for embedding in a JWT claim. Returns
     * `null` for `null` and for non-scalar, non-Stringable input.
     *
     * @param  mixed  $identifier
     * @return ?string
     */
    public static function stringify(mixed $identifier): ?string
    {
        return match (true) {
            is_string($identifier) => $identifier,
            is_int($identifier),
            is_float($identifier),
            is_bool($identifier),
            $identifier instanceof \Stringable => (string) $identifier,
            default                            => null,
        };
    }

    /**
     * Whether a known identifier equals a supplied one (a claim or a
     * caller-supplied hint) once both are coerced to strings, compared in
     * constant time. Fails closed: returns `false` when either one does not
     * coerce, such as the `null` identifier of an unsaved model.
     *
     * @param  mixed  $identifier
     * @param  mixed  $supplied
     * @return bool
     */
    public static function matches(mixed $identifier, mixed $supplied): bool
    {
        $known     = self::stringify($identifier);
        $candidate = self::stringify($supplied);

        return $known !== null && $candidate !== null && hash_equals($known, $candidate);
    }
}
