<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the shipped devices migration
 * creates, on whichever engine the suite runs against.
 *
 * The migration runs for a configured table name other than the default and
 * with the schema builder's default time precision raised, so the index names
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
final class DevicesTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped devices migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000000_create_devices_table.php';

    /** @var string Configured table name the migration runs for. */
    private const string TABLE = 'signed_in_sessions';

    /** @var array<string, bool> Every column of the table and whether it is nullable. */
    private const array COLUMNS = [
        'id'                      => false,
        'authenticatable_type'    => false,
        'authenticatable_id'      => false,
        'principal_type'          => true,
        'principal_id'            => true,
        'principal_switched_at'   => true,
        'guard'                   => true,
        'sign_in_method'          => true,
        'sign_in_identifier_type' => true,
        'client_name'             => true,
        'platform'                => true,
        'created_ip'              => true,
        'created_user_agent'      => true,
        'last_used_at'            => true,
        'last_used_ip'            => true,
        'last_used_user_agent'    => true,
        'refresh_key'             => true,
        'previous_refresh_key'    => true,
        'refresh_rotated_at'      => true,
        'signed_in_at'            => false,
        'idle_expires_at'         => false,
        'absolute_expires_at'     => false,
        'revoked_at'              => true,
        'revoked_reason'          => true,
        'created_at'              => true,
        'updated_at'              => true,
    ];

    /** @var list<string> The timestamp columns, all stored to the whole second. */
    private const array TIMESTAMP_COLUMNS = [
        'last_used_at',
        'principal_switched_at',
        'refresh_rotated_at',
        'signed_in_at',
        'idle_expires_at',
        'absolute_expires_at',
        'revoked_at',
        'created_at',
        'updated_at',
    ];

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

        Schema::dropIfExists('devices');

        config()->set('authentication.device.table', self::TABLE);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(6);

        try {
            \call_user_func([$this->loadMigration(), 'up']);
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
     * The table has exactly these columns, each with its nullability: the owner
     * and both deadlines are required, and everything a later feature or the
     * client supplies is optional.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        $columns = [];

        foreach (Schema::getColumns(self::TABLE) as $column) {
            $columns[$column['name']] = $column['nullable'];
        }

        ksort($columns);

        $expected = self::COLUMNS;

        ksort($expected);

        self::assertSame($expected, $columns);
    }

    /**
     * Every timestamp is stored to the whole second, whatever the application's
     * default time precision, so the deadlines the refresh rotation compares by
     * equality come back exactly as written.
     *
     * @return void
     */
    public function testStoresEveryTimestampToTheWholeSecond(): void
    {
        $timestamps = array_filter(
            Schema::getColumns(self::TABLE),
            static fn (array $column): bool => in_array($column['name'], self::TIMESTAMP_COLUMNS, true),
        );

        self::assertCount(count(self::TIMESTAMP_COLUMNS), $timestamps);

        foreach ($timestamps as $column) {
            self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $column['type'], $column['name']);
        }
    }

    /**
     * The string columns that hold client data are as long as the longest value
     * the package stores in them: 45 characters for an IP address, 512 for a
     * user agent, and 64 for a SHA-256 hex digest and a revocation reason.
     *
     * @return void
     */
    public function testSizesTheStringColumnsForWhatTheyHold(): void
    {
        $lengths = [
            'created_ip'           => 45,
            'last_used_ip'         => 45,
            'created_user_agent'   => 512,
            'last_used_user_agent' => 512,
            'refresh_key'          => 64,
            'previous_refresh_key' => 64,
            'revoked_reason'       => 64,
        ];

        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        foreach ($lengths as $name => $length) {
            self::assertStringContainsString("({$length})", $types[$name], $name);
        }
    }

    /**
     * The table is indexed for the lookups that need it, the owner, the
     * principal, the guard, and each pruning condition separately, and nothing
     * else: no index on the refresh digest, which is never searched.
     *
     * @return void
     */
    public function testIndexesTheOwnerPrincipalGuardAndPruningColumnsOnly(): void
    {
        $indexes = array_map(
            static fn (array $index): string => implode(',', $index['columns']),
            self::secondaryIndexes(),
        );

        sort($indexes);

        self::assertSame([
            'absolute_expires_at',
            'authenticatable_type,authenticatable_id',
            'guard',
            'idle_expires_at',
            'principal_type,principal_id',
            'revoked_at',
        ], $indexes);
    }

    /**
     * The index names include the configured table name, so the migration can
     * run for a renamed table next to another table with the same columns.
     *
     * @return void
     */
    public function testNamesIndexesAfterTheConfiguredTable(): void
    {
        $indexes = self::secondaryIndexes();

        self::assertNotEmpty($indexes);

        foreach ($indexes as $index) {
            self::assertStringStartsWith(self::TABLE . '_', $index['name']);
        }
    }

    /**
     * Every time column holds dates past January 2038, the end of MySQL's
     * `timestamp` type, so the longest accepted session lifetime and anything
     * recorded during it can be stored on every engine.
     *
     * @return void
     */
    public function testStoresEveryTimePastJanuary2038(): void
    {
        $id    = (string) Str::uuid7();
        $times = [];

        foreach (self::TIMESTAMP_COLUMNS as $offset => $column) {
            $times[$column] = sprintf('%d-02-28 23:59:59', 2039 + $offset);
        }

        DB::table(self::TABLE)->insert([
            'id'                   => $id,
            'authenticatable_type' => 'App\Models\User',
            'authenticatable_id'   => '1',
            ...$times,
        ]);

        self::assertSame($times, (array) DB::table(self::TABLE)->where('id', $id)->first(self::TIMESTAMP_COLUMNS));
    }

    /**
     * The indexes of the migrated table other than its primary key.
     *
     * @return list<array{name: string, columns: list<string>, type: string, unique: bool, primary: bool}>
     */
    private static function secondaryIndexes(): array
    {
        return array_values(array_filter(
            Schema::getIndexes(self::TABLE),
            static fn (array $index): bool => !$index['primary'],
        ));
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
            self::fail('Devices migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
