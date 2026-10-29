<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Builds a read/write split connection whose read replica lags behind the
 * primary.
 *
 * The default connection becomes `split`, which writes to one SQLite file (the
 * primary) and reads from another (the replica). The schema is created on both,
 * and every row written through `split` lands on the primary only, so a read
 * served by the replica does not see it. Tests can therefore prove that a read
 * went to the write connection by seeding through `split` and asserting the row
 * is found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithLaggingReplica
{
    /** @var string Connection that reads from the replica and writes to the primary. */
    protected const string SPLIT_CONNECTION = 'split';

    /** @var string Direct connection to the replica file. */
    protected const string REPLICA_CONNECTION = 'replica';

    /** @var string Direct connection to the primary file. */
    protected const string PRIMARY_CONNECTION = 'primary';

    /** @var string Second split connection, for models kept in a separate (landlord) database. */
    protected const string LANDLORD_CONNECTION = 'landlord';

    /** @var string Direct connection to the landlord replica file. */
    protected const string LANDLORD_REPLICA_CONNECTION = 'landlord_replica';

    /** @var string Direct connection to the landlord primary file. */
    protected const string LANDLORD_PRIMARY_CONNECTION = 'landlord_primary';

    /** @var array<int, string> Temporary SQLite files created for this test. */
    private array $laggingReplicaFiles = [];

    /**
     * Register the primary, replica, and split connections and make the split
     * connection the default.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected function configureLaggingReplica(ConfigRepository $config): void
    {
        $this->registerLaggingConnection($config, self::SPLIT_CONNECTION, self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION);

        $config->set('database.default', self::SPLIT_CONNECTION);
    }

    /**
     * Register a second lagging split connection, `landlord`, with its own
     * primary and replica files, for models that live outside the default
     * connection.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected function configureLaggingLandlordReplica(ConfigRepository $config): void
    {
        $this->registerLaggingConnection($config, self::LANDLORD_CONNECTION, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);
    }

    /**
     * Run the shipped migrations (devices, pending sign-ins and rate limits,
     * and any other shipped migration files named) against the primary and the
     * replica.
     *
     * @param  string  ...$others
     * @return void
     */
    protected function migratePackageTablesOnPrimaryAndReplica(string ...$others): void
    {
        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager = app(DatabaseManager::class);
        $files   = [
            '2026_04_06_000000_create_devices_table.php',
            '2026_04_06_000001_create_pending_sign_ins_table.php',
            '2026_04_06_000002_create_rate_limits_table.php',
            ...$others,
        ];

        foreach ($files as $file) {

            $migration = require __DIR__ . '/../../database/migrations/' . $file;

            foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
                $manager->setDefaultConnection($connection);
                $migration->up();
            }
        }

        $manager->setDefaultConnection(self::SPLIT_CONNECTION);
    }

    /**
     * Create the same table on a primary and its replica (the default pair
     * unless others are named).
     *
     * @param  string  $table
     * @param  \Closure(\Illuminate\Database\Schema\Blueprint): void  $definition
     * @param  string  $primary
     * @param  string  $replica
     * @return void
     */
    protected function createOnPrimaryAndReplica(string $table, \Closure $definition, string $primary = self::PRIMARY_CONNECTION, string $replica = self::REPLICA_CONNECTION): void
    {
        foreach ([$primary, $replica] as $connection) {
            Schema::connection($connection)->create($table, $definition);
        }
    }

    /**
     * Copy a row as it stands on a primary into its replica (the default pair
     * unless others are named), so the replica holds that version until the
     * test changes the primary again.
     *
     * @param  string  $table
     * @param  mixed  $key
     * @param  string  $primary
     * @param  string  $replica
     * @return void
     */
    protected function copyRowToReplica(string $table, mixed $key, string $primary = self::PRIMARY_CONNECTION, string $replica = self::REPLICA_CONNECTION): void
    {
        $row = DB::connection($primary)->table($table)->where('id', $key)->first();

        self::assertNotNull($row);

        DB::connection($replica)->table($table)->insert((array) $row);
    }

    /**
     * Delete the temporary SQLite files.
     *
     * @return void
     */
    protected function removeLaggingReplicaFiles(): void
    {
        foreach ($this->laggingReplicaFiles as $file) {

            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        $this->laggingReplicaFiles = [];
    }

    /**
     * Register a direct connection to a new primary file, one to a new replica
     * file, and a split connection that writes to the primary and reads from
     * the replica.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  string  $split
     * @param  string  $primaryName
     * @param  string  $replicaName
     * @return void
     */
    private function registerLaggingConnection(ConfigRepository $config, string $split, string $primaryName, string $replicaName): void
    {
        $primary = $this->createLaggingReplicaFile();
        $replica = $this->createLaggingReplicaFile();

        $config->set('database.connections.' . $primaryName, [
            'driver'   => 'sqlite',
            'database' => $primary,
            'prefix'   => '',
        ]);

        $config->set('database.connections.' . $replicaName, [
            'driver'   => 'sqlite',
            'database' => $replica,
            'prefix'   => '',
        ]);

        // The top-level `database` is what Testbench inspects; Laravel uses the
        // `read` and `write` entries for the two PDOs.
        $config->set('database.connections.' . $split, [
            'driver'   => 'sqlite',
            'database' => $primary,
            'read'     => ['database' => $replica],
            'write'    => ['database' => $primary],
            'sticky'   => false,
            'prefix'   => '',
        ]);
    }

    /**
     * Create an empty temporary SQLite database file.
     *
     * @return string
     */
    private function createLaggingReplicaFile(): string
    {
        $file = tempnam(sys_get_temp_dir(), 'auth-replica-');

        self::assertIsString($file);

        $this->laggingReplicaFiles[] = $file;

        return $file;
    }
}
