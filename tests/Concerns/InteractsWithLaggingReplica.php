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
        $primary = $this->createLaggingReplicaFile();
        $replica = $this->createLaggingReplicaFile();

        $config->set('database.connections.' . self::PRIMARY_CONNECTION, [
            'driver'   => 'sqlite',
            'database' => $primary,
            'prefix'   => '',
        ]);

        $config->set('database.connections.' . self::REPLICA_CONNECTION, [
            'driver'   => 'sqlite',
            'database' => $replica,
            'prefix'   => '',
        ]);

        // The top-level `database` is what Testbench inspects; Laravel uses the
        // `read` and `write` entries for the two PDOs.
        $config->set('database.connections.' . self::SPLIT_CONNECTION, [
            'driver'   => 'sqlite',
            'database' => $primary,
            'read'     => ['database' => $replica],
            'write'    => ['database' => $primary],
            'sticky'   => false,
            'prefix'   => '',
        ]);

        $config->set('database.default', self::SPLIT_CONNECTION);
    }

    /**
     * Run the shipped devices migration against the primary and the replica.
     *
     * @return void
     */
    protected function migrateDevicesOnPrimaryAndReplica(): void
    {
        $migration = require __DIR__ . '/../../database/migrations/2026_04_06_000000_create_devices_table.php';

        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager = app(DatabaseManager::class);

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $manager->setDefaultConnection($connection);
            $migration->up();
        }

        $manager->setDefaultConnection(self::SPLIT_CONNECTION);
    }

    /**
     * Create the same table on the primary and the replica.
     *
     * @param  string  $table
     * @param  \Closure(\Illuminate\Database\Schema\Blueprint): void  $definition
     * @return void
     */
    protected function createOnPrimaryAndReplica(string $table, \Closure $definition): void
    {
        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            Schema::connection($connection)->create($table, $definition);
        }
    }

    /**
     * Copy a row as it stands on the primary into the replica, so the replica
     * holds that version until the test changes the primary again.
     *
     * @param  string  $table
     * @param  mixed  $key
     * @return void
     */
    protected function copyRowToReplica(string $table, mixed $key): void
    {
        $row = DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $key)->first();

        self::assertNotNull($row);

        DB::connection(self::REPLICA_CONNECTION)->table($table)->insert((array) $row);
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
