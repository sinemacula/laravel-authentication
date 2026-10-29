<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the shipped identifier changes
 * migration creates, on whichever engine the suite runs against.
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
final class IdentifierChangesTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped identifier changes migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000007_create_identifier_changes_table.php';

    /** @var string Configured table name the migration runs for. */
    private const string TABLE = 'pending_email_changes';

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

        config()->set('authentication.identifier_changes.table', self::TABLE);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(6);

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
        } finally {
            Builder::defaultTimePrecision($precision);
        }
    }

    /**
     * Drop the table the test migrated and restore the configured name.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('authentication.identifier_changes.table', 'identifier_changes');

        parent::tearDown();
    }

    /**
     * The table holds the row's digest, the guard, the type, both identifiers,
     * the request, and when the change was requested and expires; only the
     * replaced identifier is nullable.
     *
     * @return void
     */
    public function testCreatesTheColumnsWithTheirNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'expires_at'        => false,
            'guard'             => false,
            'id'                => false,
            'identifier'        => false,
            'previous'          => true,
            'previous_verified' => false,
            'request_id'        => false,
            'requested_at'      => false,
            'type'              => false,
        ], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * Every time is stored to the whole second, the precision the service
     * writes and compares expiry at.
     *
     * @return void
     */
    public function testStoresEveryTimeToTheWholeSecond(): void
    {
        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        foreach (['requested_at', 'expires_at'] as $column) {
            self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $types[$column], $column);
        }

        self::insert('a', '0195f4a2-7b1c-4000-8000-000000000001');

        self::assertSame('2039-02-28 23:59:59', DB::table(self::TABLE)->value('expires_at'));
    }

    /**
     * The digest is exactly as long as a SHA-256 hex digest and the type as
     * long as the longest type; the identifiers fit an email address.
     *
     * @return void
     */
    public function testSizesTheColumns(): void
    {
        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertStringContainsString('(64)', $types['id']);
        self::assertStringContainsString('(64)', $types['type']);
        self::assertStringContainsString('(255)', $types['identifier']);
        self::assertStringContainsString('(255)', $types['previous']);
    }

    /**
     * The request is unique, and the expiry indexed for pruning, each index
     * named after the configured table.
     *
     * @return void
     */
    public function testIndexesTheRequestAndTheExpiry(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        usort($secondary, static fn (array $a, array $b): int => $a['name'] <=> $b['name']);

        self::assertSame([[['expires_at'], false], [['request_id'], true]], array_map(static fn (array $index): array => [$index['columns'], $index['unique']], $secondary));
        self::assertSame([self::TABLE . '_expires_at_index', self::TABLE . '_request_id_unique'], array_column($secondary, 'name'));

        self::insert('a', '0195f4a2-7b1c-4000-8000-000000000001');

        $this->expectException(UniqueConstraintViolationException::class);

        self::insert('b', '0195f4a2-7b1c-4000-8000-000000000001');
    }

    /**
     * Running it again for a table that exists stops with the setting to
     * change, rather than altering the table.
     *
     * @return void
     */
    public function testRefusesATableThatExists(): void
    {
        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage('Set `identifier_changes.table` in config/authentication.php to a different name');

        $this->loadMigration()->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Insert a change keyed by the repeated character for the request.
     *
     * @param  string  $key
     * @param  string  $requestId
     * @return void
     */
    private static function insert(string $key, string $requestId): void
    {
        DB::table(self::TABLE)->insert([
            'id'           => str_repeat($key, 64),
            'guard'        => 'web',
            'type'         => 'email',
            'previous'     => null,
            'identifier'   => 'ada@new.example.test',
            'request_id'   => $requestId,
            'requested_at' => '2039-02-28 23:49:59',
            'expires_at'   => '2039-02-28 23:59:59',
        ]);
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
            self::fail('Identifier changes migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
