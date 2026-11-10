<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;

/**
 * Reads a value as the database stored it, failing the test when it is not of
 * the kind the column holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsStoredValues
{
    /**
     * The instant a stored timestamp holds.
     *
     * @param  mixed  $stored
     * @return \Carbon\CarbonImmutable
     */
    protected static function storedInstant(mixed $stored): CarbonImmutable
    {
        self::assertIsString($stored, 'The stored value is no timestamp.');

        return CarbonImmutable::parse($stored);
    }

    /**
     * The integer a stored column holds, which a driver may hand back as a
     * numeric string.
     *
     * @param  mixed  $stored
     * @return int
     */
    protected static function storedInt(mixed $stored): int
    {
        self::assertIsNumeric($stored, 'The stored value is no integer.');

        return (int) $stored;
    }

    /**
     * The string a stored column holds.
     *
     * @param  mixed  $stored
     * @return string
     */
    protected static function storedString(mixed $stored): string
    {
        self::assertIsString($stored, 'The stored value is no string.');

        return $stored;
    }
}
