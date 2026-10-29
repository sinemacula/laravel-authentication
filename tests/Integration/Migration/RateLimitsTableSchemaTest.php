<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the shipped rate limits
 * migration creates, on whichever engine the suite runs against.
 *
 * The migration runs for a configured table name other than the default and
 * with the schema builder's default time precision raised, so the index name
 * and the whole-second precision are what the migration itself declares.
 *
 * Marked `#[CoversNothing]` because a migration is an anonymous class PHPUnit
 * cannot attribute coverage to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class RateLimitsTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped rate limits migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000002_create_rate_limits_table.php';

    /** @var string Configured table name the migration runs for. */
    private const string TABLE = 'attempt_counters';

    /**
     * Run the shipped migration for `TABLE`, with the schema builder's default
     * time precision raised to microseconds while it runs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::dropIfExists('rate_limits');

        config()->set('authentication.rate_limits.table', self::TABLE);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(6);

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
        } finally {
            Builder::defaultTimePrecision($precision);
        }
    }

    /**
     * Drop the table the test migrated.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * The table has exactly the digest, the count and the window end, none of
     * them nullable, and the digest is the primary key.
     *
     * @return void
     */
    public function testCreatesTheDigestCountAndWindowColumns(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame(['hits' => false, 'key' => false, 'window_ends_at' => false], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['key'], $primary[0]['columns']);
    }

    /**
     * The window end is stored to the whole second, the precision the limiter
     * computes window boundaries at and compares them by.
     *
     * @return void
     */
    public function testStoresTheWindowEndToTheWholeSecond(): void
    {
        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $types['window_ends_at']);

        DB::table(self::TABLE)->insert(['key' => str_repeat('a', 64), 'hits' => 1, 'window_ends_at' => '2039-02-28 23:59:59']);

        self::assertSame('2039-02-28 23:59:59', DB::table(self::TABLE)->value('window_ends_at'));
    }

    /**
     * The digest column is exactly as long as a SHA-256 hex digest.
     *
     * @return void
     */
    public function testSizesTheKeyForASha256Digest(): void
    {
        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertStringContainsString('(64)', $types['key']);
    }

    /**
     * The only other index is on the window end, for pruning, named after the
     * configured table.
     *
     * @return void
     */
    public function testIndexesTheWindowEndForPruningOnly(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        self::assertCount(1, $secondary);
        self::assertSame(['window_ends_at'], $secondary[0]['columns']);
        self::assertStringStartsWith(self::TABLE . '_', $secondary[0]['name']);
    }

    /**
     * The migration creates and drops the table on the configured connection.
     *
     * @return void
     */
    public function testRunsOnTheConfiguredConnection(): void
    {
        config()->set('database.connections.limits', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('authentication.rate_limits.connection', 'limits');

        $migration = $this->loadMigration();

        self::assertSame('limits', $migration->getConnection());

        $migration->up(); // @phpstan-ignore method.notFound

        self::assertTrue(Schema::connection('limits')->hasTable(self::TABLE));

        $migration->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::connection('limits')->hasTable(self::TABLE));

        config()->set('authentication.rate_limits.connection', '');

        self::assertNull($this->loadMigration()->getConnection());
    }

    /**
     * Connections that are neither a name nor `null` or empty.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedConnections(): iterable
    {
        yield from [
            'a list of names' => [['limits']],
            'true'            => [true],
            'an integer'      => [1],
        ];
    }

    /**
     * The migration refuses a connection that is not a name, as the model does,
     * instead of creating the table on the default connection.
     *
     * @param  mixed  $connection
     * @return void
     */
    #[DataProvider('provideMalformedConnections')]
    public function testRefusesAConnectionThatIsNotAName(mixed $connection): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('authentication.rate_limits.connection', $connection);

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound

            self::fail('Expected the migration to refuse the connection.');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('`authentication.rate_limits.connection` must be a connection name', $e->getMessage());
        } finally {
            config()->set('authentication.rate_limits.connection', null);
        }

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * Require the shipped anonymous-class migration file and return the
     * resulting `Migration` instance.
     *
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function loadMigration(): Migration
    {
        $migration = include self::MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('Rate limits migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
