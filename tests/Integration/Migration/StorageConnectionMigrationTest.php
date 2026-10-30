<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Models\RateLimit;
use Tests\TestCase;

/**
 * Integration tests for where the shipped migrations, run by Laravel's own
 * `migrate` and `migrate:rollback` commands, create the package's tables while
 * `authentication.storage.connection` names a connection other than the
 * default: every table on that connection, where its model reads and writes it,
 * none on the default, and the counters on a connection of their own when
 * `authentication.rate_limits.connection` names one.
 *
 * The storage connection is a second connection to the test database with a
 * table prefix of its own: a database of its own on SQLite, where each
 * in-memory connection has one, and prefixed tables beside the default
 * connection's on PostgreSQL and MySQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionMigrationTest extends TestCase
{
    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'package_store';

    /** @var string A connection of the counters' own. */
    private const string COUNTERS = 'counters';

    /** @var string A connection a `--database` run puts the tables on. */
    private const string CHOSEN = 'chosen';

    /** @var string The shipped migrations, as `--path` takes them. */
    private const string MIGRATIONS = __DIR__ . '/../../../database/migrations';

    /**
     * Every shipped model reads and writes its table on the storage connection,
     * where the migrations created it, and the default connection has none of
     * them.
     *
     * @return void
     */
    public function testTheMigrationsCreateEveryTableWhereItsModelReadsIt(): void
    {
        foreach (self::models() as $name => $model) {
            self::assertSame(self::STORAGE, $model->getConnectionName(), $name);
            self::assertTrue(Schema::connection(self::STORAGE)->hasTable($model->getTable()), $name);
            self::assertFalse(Schema::connection('testing')->hasTable($model->getTable()), $name);
            self::assertSame(0, $model->newQuery()->count(), $name);
        }
    }

    /**
     * Rolling the migrations back drops every table from the storage
     * connection, and running them again creates each there once more.
     *
     * @return void
     */
    public function testARollbackDropsTheTablesFromTheStorageConnection(): void
    {
        $this->migrate('migrate:rollback');

        foreach (self::models() as $name => $model) {
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable($model->getTable()), $name);
        }

        $this->migrate('migrate');

        foreach (self::models() as $name => $model) {
            self::assertTrue(Schema::connection(self::STORAGE)->hasTable($model->getTable()), $name);
        }
    }

    /**
     * With a connection of their own, the counters are created there while the
     * other tables stay on the storage connection.
     *
     * @return void
     */
    public function testTheCountersCanLiveOnAConnectionOfTheirOwn(): void
    {
        $this->migrate('migrate:rollback');

        config()->set('authentication.rate_limits.connection', self::COUNTERS);

        $this->migrate('migrate');

        try {
            self::assertSame(self::COUNTERS, (new RateLimit)->getConnectionName());
            self::assertTrue(Schema::connection(self::COUNTERS)->hasTable('rate_limits'));
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable('rate_limits'));
            self::assertTrue(Schema::connection(self::STORAGE)->hasTable('devices'));
            self::assertFalse(Schema::connection(self::COUNTERS)->hasTable('devices'));
        } finally {
            $this->migrate('migrate:rollback');
        }

        self::assertFalse(Schema::connection(self::COUNTERS)->hasTable('rate_limits'));
    }

    /**
     * With no storage connection named, the tables follow the connection the
     * migrator is run on, as `--database` chooses it, and so do the models that
     * use it as the default.
     *
     * @return void
     */
    public function testWithoutAStorageConnectionTheMigratorsConnectionIsUsed(): void
    {
        $this->migrate('migrate:rollback');

        config()->set('authentication.storage.connection', null);

        $this->migrate('migrate', ['--database' => self::CHOSEN]);

        try {
            foreach (self::models() as $name => $model) {
                self::assertNull($model->getConnectionName(), $name);
                self::assertTrue(Schema::connection(self::CHOSEN)->hasTable($model->getTable()), $name);
                self::assertFalse(Schema::connection(self::STORAGE)->hasTable($model->getTable()), $name);
            }
        } finally {
            $this->migrate('migrate:rollback', ['--database' => self::CHOSEN]);

            Schema::connection(self::CHOSEN)->dropIfExists('migrations');
        }

        self::assertFalse(Schema::connection(self::CHOSEN)->hasTable('devices'));
    }

    /**
     * Put the package's tables on a second connection to the test database,
     * with a prefix of its own, and register the counters' and the chosen
     * connections the same way.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config  = $app->make(ConfigRepository::class);
        $testing = $config->array('database.connections.testing');

        $config->set('database.connections.' . self::STORAGE, [...$testing, 'prefix' => 'store_']);
        $config->set('database.connections.' . self::COUNTERS, [...$testing, 'prefix' => 'counters_']);
        $config->set('database.connections.' . self::CHOSEN, [...$testing, 'prefix' => 'chosen_']);
        $config->set('authentication.storage.connection', self::STORAGE);
    }

    /**
     * Run the migration command on the shipped migrations.
     *
     * @param  string  $command
     * @param  array<string, mixed>  $options
     * @return void
     */
    private function migrate(string $command, array $options = []): void
    {
        self::assertSame(0, Artisan::call($command, ['--path' => realpath(self::MIGRATIONS), '--realpath' => true, ...$options]));
    }

    /**
     * A new instance of each shipped model, by what it stores.
     *
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     */
    private static function models(): array
    {
        return [
            'devices'            => new Device,
            'pending sign-ins'   => new PendingSignIn,
            'rate limits'        => new RateLimit,
            'one-time codes'     => new OneTimeCode,
            'passkeys'           => new Passkey,
            'passkey challenges' => new PasskeyChallenge,
            'API keys'           => new ApiKey,
            'identifier changes' => new IdentifierChange,
        ];
    }
}
