<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

use Illuminate\Database\SQLiteConnection;

/**
 * A SQLite connection whose query grammar writes each locking read's lock into
 * its SQL as a comment (`LockMarkingSQLiteGrammar`). Configured with MySQL as
 * its driver, it has the package take every lock it takes only on MySQL, and a
 * test on SQLite see it, while SQLite still runs every statement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockMarkingSQLiteConnection extends SQLiteConnection
{
    /**
     * The grammar that marks each lock.
     *
     * @return \Tests\Fixtures\Database\LockMarkingSQLiteGrammar
     */
    #[\Override]
    protected function getDefaultQueryGrammar(): LockMarkingSQLiteGrammar
    {
        return new LockMarkingSQLiteGrammar($this);
    }
}
