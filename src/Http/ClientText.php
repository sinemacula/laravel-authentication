<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

/**
 * Makes text a client supplied safe to store in a UTF-8 text column: NUL bytes
 * removed, invalid UTF-8 replaced, and cut to the column's length. PostgreSQL,
 * and MySQL in strict mode, reject invalid UTF-8 and an over-long value, and a
 * crafted header must not turn a request into a server error; PostgreSQL cannot
 * store a NUL byte in text, and through PDO a value is cut short at the first
 * one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClientText
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Clean the value for a column of the given length: NUL bytes removed,
     * invalid UTF-8 replaced, cut to `$maxLength` characters, and `null` when
     * nothing is left.
     *
     * @param  ?string  $value
     * @param  int  $maxLength
     * @return ?string
     */
    public static function clean(?string $value, int $maxLength): ?string
    {
        if ($value === null) {
            return null;
        }

        $cleaned = mb_substr(mb_scrub(str_replace("\0", '', $value), 'UTF-8'), 0, $maxLength, 'UTF-8');

        return $cleaned === '' ? null : $cleaned;
    }
}
