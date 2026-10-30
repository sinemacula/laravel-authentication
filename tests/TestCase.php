<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Shared base test case for the package's integration tests.
 *
 * Boots a minimal Testbench application with the package service provider
 * registered, the database `DB_CONNECTION` names (in-memory SQLite when unset),
 * the package's default `laravel-authentication` config block seeded, and the
 * shipped tables created. Subclasses may override `defineEnvironment` to add
 * per-test config and `defineDatabaseMigrations` (or use `setUp`) to create
 * additional tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class TestCase extends OrchestraTestCase
{
    /** @var string The connection each test runs on, in its worker's database. */
    private const string CONNECTION = 'testing';

    /** @var string The package's shipped migrations. */
    private const string MIGRATIONS = __DIR__ . '/../database/migrations';

    /** @var array<string, true> Worker databases this process has created. */
    private static array $workerDatabases = [];

    /** @var array{key: string, connection: array<string, mixed>, tables: list<string>, schema: string} The package tables this process keeps migrated, the connection settings they were kept with, and their schema as migrated. */
    private static array $keptTables = ['key' => '', 'connection' => [], 'tables' => [], 'schema' => ''];

    /** @var array<string, mixed> The storage settings the shipped migrations ran with. */
    private array $storageSettings = [];

    /**
     * Put the storage settings back as the shipped migrations ran with them,
     * destroy the application, then close its database connections.
     *
     * The settings are restored first so rolling the migrations back drops the
     * tables where they were created. The application's objects reference each
     * other, so a destroyed application's PDO is only closed once the cycles
     * are collected. Without this, a long run against a persistent database
     * holds dozens of connections at once, and parallel workers exhaust the
     * server's limit. The connections are closed after every teardown callback,
     * migration rollbacks included, so none of them finds its connection gone.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->storageSettings !== []) {
            app(ConfigRepository::class)->set($this->storageSettings);
        }

        /** @var ?\Illuminate\Database\DatabaseManager $database */
        $database = $this->app?->make('db');

        parent::tearDown();

        foreach ($database?->getConnections() ?? [] as $connection) {
            $connection->disconnect();
        }

        gc_collect_cycles();
    }

    /**
     * Register the package service provider.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [
            AuthenticationServiceProvider::class,
        ];
    }

    /**
     * Seed the database connection and package config defaults.
     *
     * Reads `DB_CONNECTION` from the environment to select the driver. Defaults
     * to in-memory SQLite when unset, so local development needs no extra
     * configuration.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('app.key', 'base64:' . base64_encode('laravel-authentication test key!'));
        $config->set('database.default', self::CONNECTION);
        $config->set('database.connections.' . self::CONNECTION, $this->databaseConnection());

        $config->set('authentication.device.model', Device::class);
        $config->set('authentication.device.table', 'devices');
        $config->set('authentication.jwt.keys', ['test-kid' => 'test-secret-key-with-at-least-32-bytes!']);
        $config->set('authentication.jwt.active_kid', 'test-kid');
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.issuer', null);
        $config->set('authentication.jwt.audience', null);
        $config->set('authentication.jwt.access_ttl_minutes', 15);
        $config->set('authentication.jwt.refresh_idle_ttl_minutes', 60 * 24 * 30);
    }

    /**
     * Run the package's shipped migrations so the default `devices`,
     * `pending_sign_ins`, `rate_limits`, `one_time_codes`, `passkeys`,
     * `passkey_challenges`, `api_keys` and `identifier_changes` tables exist
     * for tests that use the shipped models, on the connections the storage
     * settings name when they run.
     *
     * A test may point the storage settings elsewhere once the tables exist;
     * `tearDown()` puts them back before the migrations are rolled back. On a
     * persistent database (MySQL, PostgreSQL) creating and dropping the tables
     * costs more than most tests themselves, so tables on the worker's
     * connection are kept from one test to the next. Each test starts by
     * comparing their schema and migration records with what the migrations
     * left: when they match it deletes their rows, otherwise it migrates them
     * afresh. Tables on any other connection are migrated for the test and
     * dropped when it ends.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $config = app(ConfigRepository::class);

        $this->storageSettings = [
            'authentication.storage.connection'     => $config->get('authentication.storage.connection'),
            'authentication.rate_limits.connection' => $config->get('authentication.rate_limits.connection'),
        ];

        if ((getenv('DB_CONNECTION') ?: 'sqlite') === 'sqlite') {
            $this->loadMigrationsFrom(self::MIGRATIONS);

            return;
        }

        $tables     = $this->packageTables($config);
        $names      = array_column($tables, 1);
        $connection = $config->array('database.connections.' . self::CONNECTION);
        $kept       = array_unique(array_column($tables, 0)) === [self::CONNECTION];
        $key        = serialize([$names, $connection]);

        if ($kept && self::$keptTables['key'] === $key && self::$keptTables['schema'] === $this->schemaOf($names)) {
            foreach ($names as $table) {
                DB::connection(self::CONNECTION)->table($table)->delete();
            }

            return;
        }

        $this->dropKeptTables();
        $this->dropTables($tables);
        $this->forgetMigrations();
        $this->loadMigrationsFrom(self::MIGRATIONS);

        if (!$kept) {
            $this->beforeApplicationDestroyed(fn () => $this->dropTables($tables));

            return;
        }

        array_shift($this->cachedTestMigratorProcessors);

        self::$keptTables = ['key' => $key, 'connection' => $connection, 'tables' => $names, 'schema' => $this->schemaOf($names)];
    }

    /**
     * Drop the kept tables before a test class that defines its own migrations
     * sets up its database, so it starts without the package's tables, as it
     * would on a fresh database.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    #[\Override]
    protected function setUpDatabaseRequirements(\Closure $callback): void
    {
        $declaring = (new \ReflectionMethod($this, 'defineDatabaseMigrations'))->getDeclaringClass()->getName();

        if ($declaring !== self::class) {
            $this->dropKeptTables();
        }

        parent::setUpDatabaseRequirements($callback);
    }

    /**
     * Return each package table with the connection it lives on.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<array{0: string, 1: string}>
     */
    private function packageTables(ConfigRepository $config): array
    {
        $storage = StorageConnection::name()          ?? $config->string('database.default');
        $limits  = StorageConnection::forRateLimits() ?? $config->string('database.default');

        return [
            [$storage, $config->string('authentication.device.table', 'devices')],
            [$storage, $config->string('authentication.sign_in.pending_table', 'pending_sign_ins')],
            [$limits, $config->string('authentication.rate_limits.table', 'rate_limits')],
            [$storage, $config->string('authentication.codes.table', 'one_time_codes')],
            [$storage, $config->string('authentication.passkeys.table', 'passkeys')],
            [$storage, $config->string('authentication.passkeys.challenges_table', 'passkey_challenges')],
            [$storage, $config->string('authentication.api_keys.table', 'api_keys')],
            [$storage, $config->string('authentication.identifier_changes.table', 'identifier_changes')],
        ];
    }

    /**
     * Describe the given tables on the worker's connection as the database
     * reports them (their options, columns, indexes, constraints and triggers)
     * together with every run the migration repository records and its batch,
     * so a change to any of them yields a different description.
     *
     * @param  list<string>  $tables
     * @return string
     */
    private function schemaOf(array $tables): string
    {
        $connection = DB::connection(self::CONNECTION);
        $tables     = array_map(static fn (string $table): string => $connection->getTablePrefix() . $table, $tables);
        $in         = implode(', ', array_fill(0, count($tables), '?'));
        $repository = $this->migrationRepositoryTable();

        $migrations = Schema::connection(self::CONNECTION)->hasTable($repository)
            ? $connection->table($repository)->orderBy('migration')->get(['migration', 'batch'])->all()
            : [];

        return serialize([
            ...array_map(static fn (string $query): array => $connection->select($query, $tables), $this->schemaQueries($connection->getDriverName(), $in)),
            $migrations,
        ]);
    }

    /**
     * Return the queries that read the options, columns, indexes, constraints
     * and triggers of the tables the placeholders name, from PostgreSQL's
     * catalog, which answers far faster than its `information_schema` views, or
     * from MySQL's `information_schema`.
     *
     * @param  string  $driver
     * @param  string  $in
     * @return list<string>
     */
    private function schemaQueries(string $driver, string $in): array
    {
        if ($driver === 'pgsql') {
            return [
                'select relname, relkind, relpersistence, reloptions from pg_class'
                    . " where relnamespace = current_schema()::regnamespace and relname in ({$in}) order by 1",
                'select c.relname, a.attnum, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attcollation,'
                    . ' pg_get_expr(d.adbin, d.adrelid) from pg_attribute a join pg_class c on c.oid = a.attrelid'
                    . ' left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum'
                    . " where c.relnamespace = current_schema()::regnamespace and c.relname in ({$in})"
                    . ' and a.attnum > 0 and not a.attisdropped order by 1, 2',
                'select tablename, indexname, indexdef from pg_indexes'
                    . " where schemaname = current_schema() and tablename in ({$in}) order by 1, 2",
                'select c.relname, con.conname, con.contype, pg_get_constraintdef(con.oid) from pg_constraint con'
                    . ' join pg_class c on c.oid = con.conrelid'
                    . " where c.relnamespace = current_schema()::regnamespace and c.relname in ({$in}) order by 1, 2",
                'select c.relname, t.tgname, t.tgenabled, pg_get_triggerdef(t.oid) from pg_trigger t'
                    . ' join pg_class c on c.oid = t.tgrelid'
                    . " where c.relnamespace = current_schema()::regnamespace and c.relname in ({$in}) and not t.tgisinternal order by 1, 2",
            ];
        }

        return [
            'select table_name, engine, table_collation, create_options from information_schema.tables'
                . " where table_schema = database() and table_name in ({$in}) order by 1",
            "select * from information_schema.columns where table_schema = database() and table_name in ({$in})"
                . ' order by table_name, ordinal_position',
            'select table_name, index_name, non_unique, seq_in_index, column_name, sub_part, index_type, collation, is_visible, expression'
                . ' from information_schema.statistics'
                . " where table_schema = database() and table_name in ({$in}) order by 1, 2, 4",
            'select table_name, constraint_name, constraint_type from information_schema.table_constraints'
                . " where table_schema = database() and table_name in ({$in}) order by 1, 2",
            'select event_object_table, trigger_name, event_manipulation, action_timing, action_statement from information_schema.triggers'
                . " where trigger_schema = database() and event_object_table in ({$in}) order by 1, 2",
        ];
    }

    /**
     * Drop each given table on a connection this test configures.
     *
     * @param  list<array{0: string, 1: string}>  $tables
     * @return void
     */
    private function dropTables(array $tables): void
    {
        $config = app(ConfigRepository::class);

        foreach ($tables as [$connection, $table]) {
            if (!$config->has('database.connections.' . $connection)) {
                continue;
            }

            Schema::connection($connection)->dropIfExists($table);
        }
    }

    /**
     * Drop the kept tables and the migration repository, through a connection
     * built from the settings they were kept with, so they go from the worker's
     * database whatever connections the current test configures.
     *
     * @return void
     */
    private function dropKeptTables(): void
    {
        if (self::$keptTables['tables'] === []) {
            return;
        }

        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::build(self::$keptTables['connection']);
        $schema     = $connection->getSchemaBuilder();

        foreach (self::$keptTables['tables'] as $table) {
            $schema->dropIfExists($table);
        }

        $schema->dropIfExists($this->migrationRepositoryTable());

        $connection->disconnect();

        self::$keptTables = ['key' => '', 'connection' => [], 'tables' => [], 'schema' => ''];
    }

    /**
     * Drop the migration repository, so the migrations run as they would on a
     * fresh database, with no record of any earlier run.
     *
     * @return void
     */
    private function forgetMigrations(): void
    {
        /** @var \Illuminate\Database\Migrations\DatabaseMigrationRepository $repository */
        $repository = $this->app?->make('migration.repository');

        $repository->setSource(null);

        if (!$repository->repositoryExists()) {
            return;
        }

        $repository->deleteRepository();
    }

    /**
     * Return the name of the table the migration repository records runs in.
     *
     * @return string
     */
    private function migrationRepositoryTable(): string
    {
        $migrations = app(ConfigRepository::class)->get('database.migrations');

        $table = is_array($migrations) ? ($migrations['table'] ?? null) : $migrations;

        return is_string($table) ? $table : 'migrations';
    }

    /**
     * Build the database connection config from environment variables.
     *
     * @return array<string, mixed>
     */
    private function databaseConnection(): array
    {
        $driver = getenv('DB_CONNECTION') ?: 'sqlite';

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        $connection = [
            'driver'    => $driver,
            'host'      => getenv('DB_HOST') ?: '127.0.0.1',
            'port'      => getenv('DB_PORT') ?: $this->defaultPort($driver),
            'database'  => getenv('DB_DATABASE') ?: 'laravel_authentication_test',
            'username'  => getenv('DB_USERNAME') ?: 'root',
            'password'  => getenv('DB_PASSWORD') ?: '',
            'prefix'    => '',
            'charset'   => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];

        $connection['database'] = $this->workerDatabase($connection);

        return $connection;
    }

    /**
     * Return the database this process tests against.
     *
     * Tests create, empty and drop the same tables, and keep the package's
     * tables when they end, so paratest workers sharing one database would
     * collide. Each process gets its own database, named after its paratest
     * `TEST_TOKEN` (`0` outside paratest) and created afresh on first use from
     * a connection to the configured one, so nothing a previous or interrupted
     * run left behind reaches the next, and the configured database holds only
     * what tests on Testbench's own connections create.
     *
     * @param  array{driver: string, host: string, port: string, database: string, username: string, password: string}  $connection
     * @return string
     */
    private function workerDatabase(array $connection): string
    {
        $token    = getenv('TEST_TOKEN');
        $database = $connection['database'] . '_' . ($token === false || $token === '' ? '0' : $token);

        if (isset(self::$workerDatabases[$database])) {
            return $database;
        }

        $dsn = sprintf('%s:host=%s;port=%s;dbname=%s', $connection['driver'], $connection['host'], $connection['port'], $connection['database']);
        $pdo = new \PDO($dsn, $connection['username'], $connection['password']);

        $quoted = $connection['driver'] === 'pgsql' ? '"' . $database . '"' : '`' . $database . '`';

        $pdo->exec('DROP DATABASE IF EXISTS ' . $quoted . ($connection['driver'] === 'pgsql' ? ' WITH (FORCE)' : ''));
        $pdo->exec('CREATE DATABASE ' . $quoted);

        self::$workerDatabases[$database] = true;

        return $database;
    }

    /**
     * Return the default database port for the given driver.
     *
     * @param  string  $driver
     * @return string
     */
    private function defaultPort(string $driver): string
    {
        return $driver === 'pgsql' ? '5432' : '3306';
    }
}
