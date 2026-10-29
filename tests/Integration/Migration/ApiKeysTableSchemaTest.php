<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the shipped API keys migration
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
final class ApiKeysTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped API keys migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000006_create_api_keys_table.php';

    /** @var string Configured table name the migration runs for. */
    private const string TABLE = 'machine_credentials';

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

        config()->set('authentication.api_keys.table', self::TABLE);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(6);

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
        } finally {
            Builder::defaultTimePrecision($precision);
        }
    }

    /**
     * Drop the table the test migrated, and the shipped one.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);
        Schema::dropIfExists('api_keys');

        parent::tearDown();
    }

    /**
     * The table holds the public part, the secret's digest, the guard and name,
     * the owner, principal and tenant, the scopes, the expiry, last use,
     * rotation and revocation, and the timestamps; only what a key may lack is
     * nullable, and the id is the primary key.
     *
     * @return void
     */
    public function testCreatesTheColumnsWithTheirNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'authenticatable_id'   => false,
            'authenticatable_type' => false,
            'created_at'           => true,
            'expires_at'           => true,
            'guard'                => false,
            'id'                   => false,
            'last_used_at'         => true,
            'name'                 => true,
            'principal_id'         => false,
            'principal_type'       => false,
            'public_id'            => false,
            'replaced_by'          => true,
            'revoked_at'           => true,
            'rotated_at'           => true,
            'scopes'               => false,
            'secret_hash'          => false,
            'tenant_id'            => true,
            'tenant_type'          => true,
            'updated_at'           => true,
        ], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * Every time is stored to the whole second, the precision the keys are
     * written and compared at, and past January 2038.
     *
     * @return void
     */
    public function testStoresEveryTimeToTheWholeSecond(): void
    {
        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        foreach (['expires_at', 'last_used_at', 'rotated_at', 'revoked_at', 'created_at', 'updated_at'] as $column) {
            self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $types[$column], $column);
        }

        DB::table(self::TABLE)->insert([
            'id'                   => '0195f4a2-7b1c-7000-8000-000000000001',
            'public_id'            => 'ak_abcdefghijklmnop',
            'secret_hash'          => str_repeat('a', 64),
            'guard'                => 'machine',
            'authenticatable_type' => 'machine',
            'authenticatable_id'   => '1',
            'principal_type'       => 'machine',
            'principal_id'         => '1',
            'scopes'               => '[]',
            'expires_at'           => '2039-02-28 23:59:59',
        ]);

        self::assertSame('2039-02-28 23:59:59', DB::table(self::TABLE)->value('expires_at'));
    }

    /**
     * The digest column is exactly as long as a SHA-256 hex digest, and the
     * public part fits any configured prefix.
     *
     * @return void
     */
    public function testSizesTheDigestAndThePublicPart(): void
    {
        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertStringContainsString('(64)', $types['secret_hash']);
        self::assertStringContainsString('(64)', $types['public_id']);
    }

    /**
     * The public part is unique, so a key is found by one indexed lookup and a
     * colliding draw is refused; the owner and the principal are indexed for
     * listing a principal's keys; each index is named after the configured
     * table.
     *
     * @return void
     */
    public function testIndexesThePublicPartTheOwnerAndThePrincipal(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));
        $unique    = array_values(array_filter($secondary, static fn (array $index): bool => $index['unique']));

        $columns = array_map(static fn (array $index): array => $index['columns'], $secondary);

        self::assertEqualsCanonicalizing([['public_id'], ['authenticatable_type', 'authenticatable_id'], ['principal_type', 'principal_id']], $columns);
        self::assertSame([['public_id']], array_map(static fn (array $index): array => $index['columns'], $unique));
        self::assertEqualsCanonicalizing(
            [self::TABLE . '_public_id_unique', self::TABLE . '_owner_index', self::TABLE . '_principal_index'],
            array_column($secondary, 'name'),
        );
    }

    /**
     * Rolling the migration back drops the configured table.
     *
     * @return void
     */
    public function testRollsBackByDroppingTheTable(): void
    {
        $this->loadMigration()->down(); // @phpstan-ignore method.notFound

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
            self::fail('API keys migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
