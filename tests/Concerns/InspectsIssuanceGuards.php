<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;

/**
 * Reads a session row apart from its issuance guard, which every issuance
 * writes whatever it then decides.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InspectsIssuanceGuards
{
    /**
     * The row without its issuance sequence.
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
     * How many times the session's issuance guard has been written since the
     * session was inserted.
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
