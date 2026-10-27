<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the shipped devices migration
 * creates, on whichever engine the suite runs against.
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
    /** @var array<string, bool> Every column of the table and whether it is nullable. */
    private const array COLUMNS = [
        'id'                   => false,
        'authenticatable_type' => false,
        'authenticatable_id'   => false,
        'principal_type'       => true,
        'principal_id'         => true,
        'guard'                => true,
        'sign_in_method'       => true,
        'client_name'          => true,
        'platform'             => true,
        'created_ip'           => true,
        'created_user_agent'   => true,
        'last_used_at'         => true,
        'last_used_ip'         => true,
        'last_used_user_agent' => true,
        'refresh_key'          => true,
        'previous_refresh_key' => true,
        'refresh_rotated_at'   => true,
        'idle_expires_at'      => false,
        'absolute_expires_at'  => false,
        'revoked_at'           => true,
        'revoked_reason'       => true,
        'created_at'           => true,
        'updated_at'           => true,
    ];

    /** @var list<string> The timestamp columns, all stored to the whole second. */
    private const array TIMESTAMP_COLUMNS = [
        'last_used_at',
        'refresh_rotated_at',
        'idle_expires_at',
        'absolute_expires_at',
        'revoked_at',
        'created_at',
        'updated_at',
    ];

    /**
     * The table has exactly the version 2 columns, each with its nullability:
     * the owner and both deadlines are required, everything a later feature or
     * the client supplies is optional, and the operating system and MFA columns
     * are gone.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        $columns = [];

        foreach (Schema::getColumns('devices') as $column) {
            $columns[$column['name']] = $column['nullable'];
        }

        ksort($columns);

        $expected = self::COLUMNS;

        ksort($expected);

        self::assertSame($expected, $columns);
    }

    /**
     * Every timestamp is stored to the whole second, so the deadlines the
     * refresh rotation compares by equality come back exactly as written.
     *
     * @return void
     */
    public function testStoresEveryTimestampToTheWholeSecond(): void
    {
        $timestamps = array_filter(
            Schema::getColumns('devices'),
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

        $types = array_column(Schema::getColumns('devices'), 'type', 'name');

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
        foreach (self::secondaryIndexes() as $index) {
            self::assertStringStartsWith('devices_', $index['name']);
        }
    }

    /**
     * The indexes of the devices table other than its primary key.
     *
     * @return list<array{name: string, columns: list<string>, type: string, unique: bool, primary: bool}>
     */
    private static function secondaryIndexes(): array
    {
        return array_values(array_filter(
            Schema::getIndexes('devices'),
            static fn (array $index): bool => !$index['primary'],
        ));
    }
}
