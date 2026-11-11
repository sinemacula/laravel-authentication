<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;
use Tests\Fixtures\Database\LockMarkingSQLiteConnection;

/**
 * Shows which reads of a session's proofs and provenance take a shared lock, on
 * every engine a test runs on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait MarksSharedLocks
{
    /**
     * On SQLite, swap the default connection for one on the same database that
     * names MySQL as its driver and marks its locks.
     *
     * @return void
     */
    protected static function markSharedLocks(): void
    {
        $connection = DB::connection();

        if ($connection->getDriverName() !== 'sqlite') {
            return;
        }

        $name = $connection->getName() ?? '';
        $pdo  = $connection->getPdo();

        DB::extend($name, static fn (array $config): LockMarkingSQLiteConnection => new LockMarkingSQLiteConnection(
            $pdo,
            $config['database'] ?? '',
            $config['prefix']   ?? '',
            ['driver' => 'mysql', 'name' => $name] + $config,
        ));

        DB::purge($name);
    }

    /**
     * Whether the package takes a shared lock where it reads current on the
     * default connection.
     *
     * @return bool
     */
    protected static function takesSharedLocks(): bool
    {
        return in_array(DB::connection()->getDriverName(), ['mysql', 'mariadb'], true);
    }

    /**
     * Run the callback and return the statements it sent the default
     * connection, in order, in lower case.
     *
     * @param  \Closure(): mixed  $callback
     * @return list<string>
     */
    protected static function statementsDuring(\Closure $callback): array
    {
        return array_column(self::queriesDuring($callback), 0);
    }

    /**
     * Run the callback and return the statements it sent the default
     * connection, in lower case with their bindings.
     *
     * @param  \Closure(): mixed  $callback
     * @return list<array{0: string, 1: array<array-key, mixed>}>
     */
    protected static function queriesDuring(\Closure $callback): array
    {
        $connection = DB::connection();
        $logging    = $connection->logging();

        $connection->flushQueryLog();
        $connection->enableQueryLog();

        try {
            $callback();
        } finally {
            $log = $connection->getQueryLog();

            $logging || $connection->disableQueryLog();
        }

        return array_values(array_map(static fn (array $query): array => [strtolower($query['query']), $query['bindings']], $log));
    }

    /**
     * For each read of a session's proofs or provenance the callback made, in
     * order, whether it took a shared lock.
     *
     * @param  \Closure(): mixed  $callback
     * @return list<bool>
     */
    protected static function proofReadLocks(\Closure $callback): array
    {
        $reads = array_filter(self::statementsDuring($callback), self::readsProofs(...));

        return array_values(array_map(self::sharesLock(...), $reads));
    }

    /**
     * Whether the statement reads a session's proofs or provenance.
     *
     * @param  string  $sql
     * @return bool
     */
    protected static function readsProofs(string $sql): bool
    {
        return str_starts_with($sql, 'select') && (str_contains($sql, 'authentication_proofs') || str_contains($sql, 'authentication_provenance'));
    }

    /**
     * Whether the statement took a shared lock.
     *
     * @param  string  $sql
     * @return bool
     */
    protected static function sharesLock(string $sql): bool
    {
        return str_contains($sql, 'lock in share mode');
    }

    /**
     * Whether the statement took a lock for update.
     *
     * @param  string  $sql
     * @return bool
     */
    protected static function locksForUpdate(string $sql): bool
    {
        return str_contains($sql, 'for update');
    }
}
