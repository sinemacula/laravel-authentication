<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;

/**
 * Reads a session row apart from its issuance guard. Every refresh and switch
 * that finds the session writes the guard first, whatever it then decides, and
 * every other issuance of a token for it writes the guard too, so a test that
 * holds a refused or repeated issuance to "nothing written" compares the row
 * without the guard, and counts the guard's writes on their own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InspectsIssuanceGuards
{
    /**
     * The row without its issuance sequence: the session's state as every
     * decision of an issuance reads and writes it.
     *
     * @param  array<string, mixed>  $row
     * @return array<string, mixed>
     */
    protected static function withoutIssuanceGuard(array $row): array
    {
        unset($row['issuance_sequence']);

        return $row;
    }

    /**
     * How many times the issuance guard of the session stored under the key has
     * been written since the session was inserted.
     *
     * @param  mixed  $key
     * @param  string  $table
     * @return int
     */
    protected static function issuanceGuardWrites(mixed $key, string $table = 'authentication_sessions'): int
    {
        $sequence = DB::table($table)->where('id', $key)->value('issuance_sequence');

        self::assertIsNumeric($sequence);

        return (int) $sequence;
    }
}
