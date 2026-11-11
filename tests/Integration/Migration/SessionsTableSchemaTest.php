<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\Concerns\RunsMigrationSteps;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the sessions migration creates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class SessionsTableSchemaTest extends TestCase
{
    use RunsMigrationSteps;

    /** @var string Absolute path to the shipped sessions migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000000_create_authentication_sessions_table.php';

    /** @var string Configured table name the migration runs for. */
    private const string TABLE = 'signed_in_sessions';

    /** @var array<string, bool> Every column of the table and whether it is nullable. */
    private const array COLUMNS = [
        'id'                      => false,
        'generation'              => false,
        'authenticatable_type'    => false,
        'authenticatable_id'      => false,
        'principal_type'          => true,
        'principal_id'            => true,
        'status'                  => false,
        'requires'                => true,
        'pending_key'             => true,
        'supersedes_session_id'   => true,
        'supersedes_refresh_key'  => true,
        'attempt_windows'         => true,
        'tenant_id'               => true,
        'tenant_policy_version'   => true,
        'switched_at'             => true,
        'issuance_sequence'       => false,
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
        'absolute_expires_at'     => true,
        'revoked_at'              => true,
        'revoked_reason'          => true,
        'created_at'              => true,
        'updated_at'              => true,
    ];

    /** @var list<string> The timestamp columns, all stored to the whole second. */
    private const array TIMESTAMP_COLUMNS = [
        'last_used_at',
        'switched_at',
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

        Schema::dropIfExists('authentication_sessions');

        config()->set('authentication.session.table', self::TABLE);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(6);

        try {
            self::runMigrationStep($this->loadMigration());
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
     * The table has exactly these columns, each with its nullability.
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
     * Every timestamp is stored to the whole second, so the rotation's equality
     * checks hold.
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
     * The string columns are as long as the longest value the package stores in
     * them.
     *
     * @return void
     */
    public function testSizesTheStringColumnsForWhatTheyHold(): void
    {
        $lengths = [
            'created_ip'             => 45,
            'last_used_ip'           => 45,
            'created_user_agent'     => 512,
            'last_used_user_agent'   => 512,
            'refresh_key'            => 64,
            'previous_refresh_key'   => 64,
            'revoked_reason'         => 64,
            'status'                 => 16,
            'requires'               => 64,
            'pending_key'            => 64,
            'supersedes_refresh_key' => 64,
            'tenant_policy_version'  => 64,
            'tenant_id'              => 255,
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
     * Only the owner, principal, guard, tenant and pruning columns are indexed.
     *
     * @return void
     */
    public function testIndexesTheOwnerPrincipalGuardTenantAndPruningColumnsOnly(): void
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
            'tenant_id',
        ], $indexes);
    }

    /**
     * Each index is named after the configured table.
     *
     * @return void
     */
    public function testNamesIndexesAfterTheConfiguredTable(): void
    {
        self::assertSame(self::indexNames(self::TABLE), self::secondaryIndexNames(self::TABLE));
    }

    /**
     * A 47-character table name migrates with every index name within
     * PostgreSQL's 63-character limit, which truncates silently.
     *
     * @return void
     */
    public function testMigratesATableNameOfFortySevenCharacters(): void
    {
        $table = str_repeat('s', 47);

        config()->set('authentication.session.table', $table);

        try {
            self::runMigrationStep($this->loadMigration());

            self::assertSame(self::indexNames($table), self::secondaryIndexNames($table));
        } finally {
            Schema::dropIfExists($table);
        }
    }

    /**
     * Every time column holds dates past January 2038, the end of MySQL's
     * `timestamp` type.
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
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => 'App\Models\User',
            'authenticatable_id'   => '1',
            ...$times,
        ]);

        self::assertSame($times, (array) DB::table(self::TABLE)->where('id', $id)->first(self::TIMESTAMP_COLUMNS));
    }

    /**
     * A row written without a status reads as active, so only a row the package
     * makes pending is ever taken for one.
     *
     * @return void
     */
    public function testAStatusDefaultsToActive(): void
    {
        $id = (string) Str::uuid7();

        DB::table(self::TABLE)->insert([
            'id'                   => $id,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => 'App\Models\User',
            'authenticatable_id'   => '1',
            'signed_in_at'         => '2026-04-06 12:00:00',
            'idle_expires_at'      => '2026-04-06 13:00:00',
        ]);

        self::assertSame('active', DB::table(self::TABLE)->where('id', $id)->value('status'));
    }

    /**
     * The issuance guard is an unindexed, required big integer starting at
     * zero.
     *
     * @return void
     */
    public function testTheIssuanceGuardIsARequiredBigIntegerStartingAtZero(): void
    {
        $id     = (string) Str::uuid7();
        $column = array_column(Schema::getColumns(self::TABLE), null, 'name')['issuance_sequence'] ?? null;

        self::assertIsArray($column);
        self::assertFalse($column['nullable']);
        self::assertContains(strtolower($column['type_name']), ['bigint', 'int8', 'integer']);

        if (Schema::getConnection()->getDriverName() === 'mysql') {
            self::assertStringContainsString('unsigned', $column['type']);
        }

        DB::table(self::TABLE)->insert([
            'id'                   => $id,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => 'App\Models\User',
            'authenticatable_id'   => '1',
            'signed_in_at'         => '2026-04-06 12:00:00',
            'idle_expires_at'      => '2026-04-06 13:00:00',
        ]);

        self::assertEquals(0, DB::table(self::TABLE)->where('id', $id)->value('issuance_sequence'));

        DB::table(self::TABLE)->where('id', $id)->increment('issuance_sequence');

        self::assertEquals(1, DB::table(self::TABLE)->where('id', $id)->value('issuance_sequence'));
    }

    /**
     * The indexes of the migrated table other than its primary key.
     *
     * @param  string  $table
     * @return list<array{name: string, columns: list<string>, type: string, unique: bool, primary: bool}>
     */
    private static function secondaryIndexes(string $table = self::TABLE): array
    {
        return array_values(array_filter(
            Schema::getIndexes($table),
            static fn (array $index): bool => !$index['primary'],
        ));
    }

    /**
     * The columns of each index of the migrated table other than its primary
     * key, by the index's name, sorted by name.
     *
     * @param  string  $table
     * @return array<string, string>
     */
    private static function secondaryIndexNames(string $table): array
    {
        $names = [];

        foreach (self::secondaryIndexes($table) as $index) {
            $names[$index['name']] = implode(',', $index['columns']);
        }

        ksort($names);

        return $names;
    }

    /**
     * The columns of each index the migration declares for the table, by the
     * index's name, sorted by name.
     *
     * @param  string  $table
     * @return array<string, string>
     */
    private static function indexNames(string $table): array
    {
        return [
            $table . '_absolute_index'  => 'absolute_expires_at',
            $table . '_guard_index'     => 'guard',
            $table . '_idle_index'      => 'idle_expires_at',
            $table . '_owner_index'     => 'authenticatable_type,authenticatable_id',
            $table . '_principal_index' => 'principal_type,principal_id',
            $table . '_revoked_index'   => 'revoked_at',
            $table . '_tenant_index'    => 'tenant_id',
        ];
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
            self::fail('Sessions migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
