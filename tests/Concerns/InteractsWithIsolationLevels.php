<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\DeadlockException;
use Illuminate\Support\Facades\DB;

/**
 * A caller's transaction at a given isolation level on the default connection,
 * and the serialisation failure PostgreSQL raises in it at REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithIsolationLevels
{
    /**
     * Rows of `[isolation level]`: PostgreSQL's default and MySQL's default.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideIsolationLevels(): iterable
    {
        yield 'read committed' => ['read committed'];

        yield 'repeatable read' => ['repeatable read'];
    }

    /**
     * Begin a transaction at the isolation level on the default connection.
     *
     * MySQL sets the level for the next transaction, PostgreSQL inside it.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    protected static function beginTransactionAt(string $level): void
    {
        $driver = DB::connection()->getDriverName();

        if ($driver === 'mysql') {
            DB::statement('set transaction isolation level ' . $level);
        }

        DB::beginTransaction();

        if ($driver !== 'pgsql') {
            return;
        }

        DB::statement('set transaction isolation level ' . $level);
    }

    /**
     * Whether every read at the isolation level, a locking one included, sees
     * the snapshot the transaction took at its first statement.
     *
     * @param  string  $level
     * @return bool
     */
    protected static function readsASnapshot(string $level): bool
    {
        return DB::connection()->getDriverName() === 'pgsql' && $level !== 'read committed';
    }

    /**
     * Run the work in the open transaction, roll it back and return the
     * SQLSTATE it failed to serialise with.
     *
     * @param  \Closure(): mixed  $work
     * @return ?string
     *
     * @throws \Throwable
     */
    protected static function serializationFailure(\Closure $work): ?string
    {
        try {
            $work();
        } catch (DeadlockException $exception) {
            return (string) $exception->getPrevious()?->getCode();
        } finally {
            DB::rollBack();
        }

        return null;
    }

    /**
     * Have a lock wait on the named connection give up after two seconds.
     *
     * @param  string  $name
     * @return void
     */
    protected static function limitLockWaits(string $name): void
    {
        $connection = DB::connection($name);

        $connection->statement(match ($connection->getDriverName()) {
            'mysql' => 'set session innodb_lock_wait_timeout = 2',
            default => 'set lock_timeout = \'2s\'',
        });
    }
}
