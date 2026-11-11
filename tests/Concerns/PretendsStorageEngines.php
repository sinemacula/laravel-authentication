<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;

/**
 * Runs package code in Laravel's pretend mode against a storage connection of
 * another engine, recording the SQL its grammar compiles.
 *
 * Pretend mode quotes bindings for its log, so an in-memory SQLite handle is
 * given to quote with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait PretendsStorageEngines
{
    /**
     * Rows of `[driver]`, one per engine the package supports.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideStorageEngines(): iterable
    {
        yield 'mysql' => ['mysql'];

        yield 'mariadb' => ['mariadb'];

        yield 'pgsql' => ['pgsql'];

        yield 'sqlite' => ['sqlite'];

        yield 'sqlsrv' => ['sqlsrv'];
    }

    /**
     * Run the callback with the storage connection pointed at a pretended one
     * of the driver, and return the statements it sent that connection.
     *
     * @param  string  $driver
     * @param  \Closure(): void  $callback
     * @return list<string>
     */
    protected static function statementsOn(string $driver, \Closure $callback): array
    {
        $config   = app(ConfigRepository::class);
        $name     = 'pretended_' . $driver;
        $previous = $config->get('authentication.storage.connection');

        $config->set('database.connections.' . $name, [
            'driver'   => $driver,
            'host'     => '127.0.0.1',
            'port'     => '1',
            'database' => $driver === 'sqlite' ? ':memory:' : 'pretended',
            'username' => 'pretended',
            'password' => '',
            'prefix'   => '',
        ]);
        $config->set('authentication.storage.connection', $name);

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements, $name): void {
            if ($query->connectionName !== $name) {
                return;
            }

            $statements[] = $query->sql;
        });

        $quoting    = new \PDO('sqlite::memory:');
        $connection = DB::connection($name)->setPdo($quoting)->setReadPdo($quoting);

        try {
            $connection->pretend(static function () use ($callback): void {
                $callback();
            });
        } finally {
            $config->set('authentication.storage.connection', $previous);

            DB::purge($name);
        }

        return $statements;
    }
}
