<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

/**
 * Coerces contract identifiers into JWT claim strings and compares them.
 *
 * RFC 7519 requires `sub` to be a `StringOrURI`; the contract getters return
 * `mixed`.
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
     * Coerce an identifier to a claim string, or `null` when it cannot be.
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
     * Whether two identifiers match as strings, in constant time; `false` when
     * either does not coerce.
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
