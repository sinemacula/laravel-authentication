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
 * Integration tests for the shape of the table the shipped one-time codes
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
final class OneTimeCodesTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped one-time codes migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000003_create_one_time_codes_table.php';

    /** @var string Configured table name the migration runs for. */
    private const string TABLE = 'sign_in_codes';

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

        Schema::dropIfExists('one_time_codes');

        config()->set('authentication.codes.table', self::TABLE);

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
     * The table holds the binding digest, the purpose and guard, the issuance,
     * the code's hash, the attempts, and when the code was issued, expires and
     * was used; only the use is nullable. No column holds an identifier or a
     * code in clear.
     *
     * @return void
     */
    public function testCreatesTheColumnsWithTheirNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'attempts'    => false,
            'code_hash'   => false,
            'consumed_at' => true,
            'expires_at'  => false,
            'guard'       => false,
            'id'          => false,
            'issue_id'    => false,
            'issued_at'   => false,
            'purpose'     => false,
        ], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * Every time is stored to the whole second, the precision the engine writes
     * and compares expiry and the resend cooldown at.
     *
     * @return void
     */
    public function testStoresEveryTimeToTheWholeSecond(): void
    {
        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        foreach (['issued_at', 'expires_at', 'consumed_at'] as $column) {
            self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $types[$column], $column);
        }

        DB::table(self::TABLE)->insert([
            'id'         => str_repeat('a', 64),
            'purpose'    => 'verify_identifier',
            'guard'      => 'api',
            'issue_id'   => '0195f4a2-7b1c-4000-8000-000000000001',
            'code_hash'  => str_repeat('b', 64),
            'attempts'   => 20,
            'issued_at'  => '2039-02-28 23:49:59',
            'expires_at' => '2039-02-28 23:59:59',
        ]);

        self::assertSame('2039-02-28 23:59:59', DB::table(self::TABLE)->value('expires_at'));
    }

    /**
     * The digest columns are exactly as long as an HMAC-SHA256 hex digest, and
     * the purpose fits the longest purpose.
     *
     * @return void
     */
    public function testSizesTheDigestColumns(): void
    {
        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertStringContainsString('(64)', $types['id']);
        self::assertStringContainsString('(64)', $types['code_hash']);
        self::assertStringContainsString('(32)', $types['purpose']);
    }

    /**
     * The one other index is on the expiry, for pruning, named after the
     * configured table.
     *
     * @return void
     */
    public function testIndexesTheExpiry(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        self::assertSame([['expires_at']], array_map(static fn (array $index): array => $index['columns'], $secondary));
        self::assertSame([self::TABLE . '_expires_at_index'], array_column($secondary, 'name'));
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
            self::fail('One-time codes migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
