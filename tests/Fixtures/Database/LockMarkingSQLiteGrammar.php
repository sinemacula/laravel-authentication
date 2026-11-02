<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;

/**
 * SQLite's query grammar, but writing a locking read's lock into its SQL as a
 * comment naming it (`for update`, `lock in share mode`) where SQLite's own
 * grammar drops it, so a test on SQLite can see which reads lock the row, as
 * the SQL of the other engines shows, while SQLite still runs them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockMarkingSQLiteGrammar extends SQLiteGrammar
{
    /**
     * Compile the lock as a comment naming it.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool|string  $value
     * @return string
     */
    #[\Override]
    protected function compileLock(Builder $query, $value): string
    {
        if (is_string($value)) {
            return '/* ' . $value . ' */';
        }

        return $value ? '/* for update */' : '/* lock in share mode */';
    }
}
