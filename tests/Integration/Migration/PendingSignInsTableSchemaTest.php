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
 * Integration tests for the shape of the table the shipped pending sign-ins
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
final class PendingSignInsTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped pending sign-ins migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000001_create_pending_sign_ins_table.php';

    /** @var string Configured table name the migration runs for. */
    private const string TABLE = 'factor_waits';

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

        Schema::dropIfExists('pending_sign_ins');

        config()->set('authentication.sign_in.pending_table', self::TABLE);

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
     * The table holds the token digest and purpose, the guard, method and
     * identifier type, the owner and principal, the client, the proven device,
     * the expiry and the timestamps; only what a sign-in may lack is nullable.
     *
     * @return void
     */
    public function testCreatesTheColumnsWithTheirNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'attempt_windows'      => true,
            'authenticatable_id'   => false,
            'authenticatable_type' => false,
            'client_name'          => true,
            'created_at'           => true,
            'created_ip'           => true,
            'created_user_agent'   => true,
            'device_id'            => true,
            'device_refresh_key'   => true,
            'expires_at'           => false,
            'guard'                => false,
            'id'                   => false,
            'identifier_type'      => true,
            'platform'             => true,
            'principal_id'         => false,
            'principal_type'       => false,
            'purpose'              => false,
            'sign_in_method'       => false,
            'token_digest'         => false,
            'updated_at'           => true,
        ], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * Every time is stored to the whole second, the precision the session
     * service writes and compares the expiry at.
     *
     * @return void
     */
    public function testStoresEveryTimeToTheWholeSecond(): void
    {
        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        foreach (['expires_at', 'created_at', 'updated_at'] as $column) {
            self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $types[$column], $column);
        }

        DB::table(self::TABLE)->insert([
            'id'                   => '0195f4a2-7b1c-7000-8000-000000000001',
            'token_digest'         => str_repeat('a', 64),
            'purpose'              => 'additional_factor',
            'guard'                => 'api',
            'sign_in_method'       => 'password',
            'authenticatable_type' => 'identity',
            'authenticatable_id'   => '1',
            'principal_type'       => 'identity',
            'principal_id'         => '1',
            'expires_at'           => '2039-02-28 23:59:59',
        ]);

        self::assertSame('2039-02-28 23:59:59', DB::table(self::TABLE)->value('expires_at'));
    }

    /**
     * The digest columns are exactly as long as a SHA-256 hex digest, and the
     * client columns as long as an IPv6 address and a stored user agent.
     *
     * @return void
     */
    public function testSizesTheDigestAndClientColumns(): void
    {
        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertStringContainsString('(64)', $types['token_digest']);
        self::assertStringContainsString('(64)', $types['device_refresh_key']);
        self::assertStringContainsString('(64)', $types['purpose']);
        self::assertStringContainsString('(45)', $types['created_ip']);
        self::assertStringContainsString('(512)', $types['created_user_agent']);
    }

    /**
     * The only other index is on the expiry, for pruning, named after the
     * configured table.
     *
     * @return void
     */
    public function testIndexesTheExpiryForPruningOnly(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        self::assertCount(1, $secondary);
        self::assertSame(['expires_at'], $secondary[0]['columns']);
        self::assertStringStartsWith(self::TABLE . '_', $secondary[0]['name']);
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
            self::fail('Pending sign-ins migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
