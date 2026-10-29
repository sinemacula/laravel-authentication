<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Identifiers;

/**
 * The names identifier types go by: `email`, `phone`, or any other a normaliser
 * is registered under. A type also names the identity's column holding the
 * identifier and the `<type>_verified_at` column recording its verification, so
 * a name is restricted to what is safe as a column name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class IdentifierType
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the name is a valid identifier type: a lower-case letter followed
     * by lower-case letters, digits and underscores.
     *
     * @param  string  $type
     * @return bool
     */
    public static function isValid(string $type): bool
    {
        return preg_match('/^[a-z][a-z0-9_]*$/D', $type) === 1;
    }

    /**
     * Return the name when it is a valid identifier type, and throw otherwise.
     *
     * @param  string  $type
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function assertValid(string $type): string
    {
        if (!self::isValid($type)) {
            throw new \InvalidArgumentException("Identifier type [{$type}] must be a lower-case letter followed by lower-case letters, digits and underscores.");
        }

        return $type;
    }
}
