<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;

/**
 * SQLite's query grammar, writing a locking read's lock into its SQL as a
 * comment where SQLite's own grammar drops it.
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
