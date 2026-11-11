<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

use Illuminate\Database\SQLiteConnection;

/**
 * A SQLite connection that writes each locking read's lock into its SQL;
 * configured with the MySQL driver, it takes MySQL's locks.
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
