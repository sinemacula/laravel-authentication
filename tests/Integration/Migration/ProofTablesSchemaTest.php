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
 * Integration tests for the shape of the tables the shipped proofs and
 * provenance migrations create, on whichever engine the suite runs against.
 *
 * Each migration runs for a configured table name other than the default, with
 * the schema builder's default time precision raised, so the index names and
 * the whole-second precision are what the migrations themselves declare.
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
final class ProofTablesSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped proofs migration file. */
    private const string PROOFS_MIGRATION = __DIR__ . '/../../../database/migrations/2026_04_06_000008_create_authentication_proofs_table.php';

    /** @var string Absolute path to the shipped provenance migration file. */
    private const string PROVENANCE_MIGRATION = __DIR__ . '/../../../database/migrations/2026_04_06_000009_create_authentication_provenance_table.php';

    /** @var string Configured proofs table name the migration runs for. */
    private const string PROOFS = 'session_proof_records';

    /** @var string Configured provenance table name the migration runs for. */
    private const string PROVENANCE = 'session_provenance_records';

    /**
     * Run both shipped migrations for the configured names, with the schema
     * builder's default time precision raised to microseconds while they run.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('authentication.proofs.table', self::PROOFS);
        config()->set('authentication.proofs.provenance_table', self::PROVENANCE);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(6);

        try {
            \call_user_func([self::load(self::PROOFS_MIGRATION), 'up']);
            \call_user_func([self::load(self::PROVENANCE_MIGRATION), 'up']);
        } finally {
            Builder::defaultTimePrecision($precision);
        }
    }

    /**
     * Drop the tables the test migrated.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::PROOFS);
        Schema::dropIfExists(self::PROVENANCE);

        parent::tearDown();
    }

    /**
     * The proofs table holds each proof's session, kind and purpose, method,
     * channel and factor, observations, evaluation, `amr` values, binding, time
     * and voiding; only what a proof may lack is nullable (each observation and
     * the evaluation, which are `null` when not observed or not an adapter's),
     * and the id is the primary key.
     *
     * @return void
     */
    public function testTheProofsTableHasItsColumnsAndNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::PROOFS), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'accepted'             => true,
            'authenticatable_id'   => false,
            'authenticatable_type' => false,
            'authenticated_at'     => false,
            'backup_eligible'      => true,
            'backup_state'         => true,
            'channel_kind'         => false,
            'channel_reference'    => true,
            'created_at'           => true,
            'factor_reference'     => true,
            'guard'                => false,
            'id'                   => false,
            'key_protection'       => true,
            'kind'                 => false,
            'method'               => false,
            'methods'              => false,
            'multifactor'          => true,
            'phishing_resistant'   => true,
            'purpose'              => false,
            'session_id'           => false,
            'user_presence'        => true,
            'user_verification'    => true,
            'voided_at'            => true,
        ], $columns);

        self::assertSame([['id']], self::primaryColumns(self::PROOFS));
    }

    /**
     * The provenance table holds one row per session: the connection and its
     * tenant, the provider's time and deadline, the accepted evidence and the
     * policy version; only the session and the connection are required.
     *
     * @return void
     */
    public function testTheProvenanceTableHasItsColumnsAndNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::PROVENANCE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'accepted_evidence'           => true,
            'connection_id'               => false,
            'created_at'                  => true,
            'policy_version'              => true,
            'provider_authenticated_at'   => true,
            'provider_session_expires_at' => true,
            'session_id'                  => false,
            'tenant_id'                   => true,
        ], $columns);

        self::assertSame([['session_id']], self::primaryColumns(self::PROVENANCE));
    }

    /**
     * Every time is stored to the whole second, as the session's own are, and
     * past January 2038.
     *
     * @return void
     */
    public function testStoresEveryTimeToTheWholeSecond(): void
    {
        $proofs     = array_column(Schema::getColumns(self::PROOFS), 'type', 'name');
        $provenance = array_column(Schema::getColumns(self::PROVENANCE), 'type', 'name');

        foreach (['authenticated_at', 'voided_at', 'created_at'] as $column) {
            self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $proofs[$column], $column);
        }

        foreach (['provider_authenticated_at', 'provider_session_expires_at', 'created_at'] as $column) {
            self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $provenance[$column], $column);
        }

        DB::table(self::PROVENANCE)->insert(['session_id' => 's-1', 'connection_id' => 'c-1', 'provider_session_expires_at' => '2039-02-28 23:59:59']);

        self::assertSame('2039-02-28 23:59:59', DB::table(self::PROVENANCE)->value('provider_session_expires_at'));
    }

    /**
     * The string columns are as long as what they hold: a channel reference of
     * 255 characters, a kind, a purpose and a key protection, the `amr` list's
     * JSON, and a policy version of 64. The session key, owner, guard and
     * factor reference hold 255 characters, which on MySQL and MariaDB, where
     * they are binary, is 1020 bytes.
     *
     * @return void
     */
    public function testSizesTheStringColumns(): void
    {
        $driver = Schema::getConnection()->getDriverName();

        if ($driver === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $proofs     = array_column(Schema::getColumns(self::PROOFS), 'type', 'name');
        $provenance = array_column(Schema::getColumns(self::PROVENANCE), 'type', 'name');
        $binding    = in_array($driver, ['mysql', 'mariadb'], true) ? '(1020)' : '(255)';

        foreach (['session_id', 'authenticatable_type', 'authenticatable_id', 'guard', 'factor_reference'] as $column) {
            self::assertStringContainsString($binding, $proofs[$column], $column);
        }

        self::assertStringContainsString($binding, $provenance['session_id']);

        self::assertStringContainsString('(40)', $proofs['kind']);
        self::assertStringContainsString('(32)', $proofs['purpose']);
        self::assertStringContainsString('(32)', $proofs['channel_kind']);
        self::assertStringContainsString('(255)', $proofs['channel_reference']);
        self::assertStringContainsString('(16)', $proofs['key_protection']);
        self::assertStringContainsString('(1024)', $proofs['methods']);
        self::assertStringContainsString('(64)', $provenance['policy_version']);
        self::assertStringContainsString('(255)', $provenance['connection_id']);
    }

    /**
     * The proofs are indexed by session, kind and time, for the claims and the
     * freshness reads, and the provenance by connection and by tenant and
     * connection; each index is named after the configured table.
     *
     * @return void
     */
    public function testIndexesTheirLookups(): void
    {
        self::assertSame([[self::PROOFS . '_session_index', ['session_id', 'kind', 'authenticated_at']]], self::secondaryIndexes(self::PROOFS));
        self::assertEqualsCanonicalizing(
            [[self::PROVENANCE . '_provider_index', ['connection_id']], [self::PROVENANCE . '_tenant_index', ['tenant_id', 'connection_id']]],
            self::secondaryIndexes(self::PROVENANCE),
        );
    }

    /**
     * The session key, the guard, the owner, the factor reference and the `amr`
     * values compare byte for byte on every engine, MySQL's default
     * case-insensitive collations and its padding `utf8mb4_bin` included: a
     * lookup of one finds no value that differs from it only in case or by a
     * trailing space, a group keeps such values apart, and provenances whose
     * session keys differ only in those are all kept.
     *
     * @return void
     */
    public function testComparesTheBindingAndTheValuesByteForByte(): void
    {
        $row = static fn (string $id, string $session, string $type, string $owner, string $guard, string $methods): array => [
            'id'                   => $id,
            'session_id'           => $session,
            'kind'                 => 'first_factor',
            'purpose'              => 'sign_in',
            'method'               => 'password',
            'channel_kind'         => 'password',
            'factor_reference'     => $owner,
            'methods'              => $methods,
            'authenticatable_type' => $type,
            'authenticatable_id'   => $owner,
            'guard'                => $guard,
            'authenticated_at'     => '2026-04-06 12:00:00',
        ];

        DB::table(self::PROOFS)->insert([
            $row('0196a3c0-0000-7000-8000-000000000001', 'abc', 'App\User', 'alice', 'api', '["urn:example:a"]'),
            $row('0196a3c0-0000-7000-8000-000000000002', 'ABC', 'App\USER', 'Alice', 'API', '["urn:example:A"]'),
            $row('0196a3c0-0000-7000-8000-000000000003', 'abc ', 'App\User ', 'alice ', 'api ', '["urn:example:a"] '),
        ]);

        $columns = [
            'session_id'           => 'abc',
            'authenticatable_type' => 'App\User',
            'authenticatable_id'   => 'alice',
            'guard'                => 'api',
            'factor_reference'     => 'alice',
            'methods'              => '["urn:example:a"]',
        ];

        foreach ($columns as $column => $value) {
            self::assertSame(1, DB::table(self::PROOFS)->where($column, $value)->count(), $column);
        }

        self::assertSame(1, DB::table(self::PROOFS)->whereIn('session_id', ['abc'])->count());
        self::assertSame(2, DB::table(self::PROOFS)->where('factor_reference', '<>', 'alice')->count());
        self::assertCount(3, DB::table(self::PROOFS)->select('methods')->groupBy('methods')->get());

        DB::table(self::PROVENANCE)->insert([
            ['session_id' => 'abc', 'connection_id' => 'c-1'],
            ['session_id' => 'ABC', 'connection_id' => 'c-2'],
            ['session_id' => 'abc ', 'connection_id' => 'c-3'],
        ]);

        self::assertSame('c-1', DB::table(self::PROVENANCE)->where('session_id', 'abc')->value('connection_id'));
        self::assertSame(3, DB::table(self::PROVENANCE)->count());
    }

    /**
     * A session key, owner and guard of 255 characters that each take four
     * bytes are stored and found again whole on every engine, and so is a
     * provenance under that key: a binary column on MySQL and MariaDB holds
     * what a string column of 255 characters holds elsewhere.
     *
     * @return void
     */
    public function testHoldsBindingsOf255FourByteCharacters(): void
    {
        $session = str_repeat("\u{1F511}", 255);
        $type    = str_repeat("\u{1D4AF}", 255);
        $owner   = str_repeat("\u{1F464}", 255);
        $guard   = str_repeat("\u{1F6E1}", 255);

        DB::table(self::PROOFS)->insert([
            'id'                   => '0196a3c0-0000-7000-8000-000000000001',
            'session_id'           => $session,
            'kind'                 => 'first_factor',
            'purpose'              => 'sign_in',
            'method'               => 'password',
            'channel_kind'         => 'password',
            'methods'              => '["pwd"]',
            'authenticatable_type' => $type,
            'authenticatable_id'   => $owner,
            'guard'                => $guard,
            'authenticated_at'     => '2026-04-06 12:00:00',
        ]);

        DB::table(self::PROVENANCE)->insert(['session_id' => $session, 'connection_id' => 'c-1']);

        $stored = (array) DB::table(self::PROOFS)
            ->where(['session_id' => $session, 'authenticatable_type' => $type, 'authenticatable_id' => $owner, 'guard' => $guard])
            ->sole(['session_id', 'authenticatable_type', 'authenticatable_id', 'guard']);

        self::assertSame(['session_id' => $session, 'authenticatable_type' => $type, 'authenticatable_id' => $owner, 'guard' => $guard], $stored);
        self::assertSame($session, DB::table(self::PROVENANCE)->where('session_id', $session)->value('session_id'));
    }

    /**
     * Configured table names of 47 characters migrate on every engine with
     * every index under its own full name, within PostgreSQL's 63 characters.
     *
     * @return void
     */
    public function testMigratesTableNamesOfFortySevenCharacters(): void
    {
        $proofs     = str_repeat('p', 47);
        $provenance = str_repeat('q', 47);

        config()->set('authentication.proofs.table', $proofs);
        config()->set('authentication.proofs.provenance_table', $provenance);

        try {
            \call_user_func([self::load(self::PROOFS_MIGRATION), 'up']);
            \call_user_func([self::load(self::PROVENANCE_MIGRATION), 'up']);

            self::assertSame([$proofs . '_session_index'], array_column(self::secondaryIndexes($proofs), 0));
            self::assertEqualsCanonicalizing([$provenance . '_provider_index', $provenance . '_tenant_index'], array_column(self::secondaryIndexes($provenance), 0));
        } finally {
            Schema::dropIfExists($proofs);
            Schema::dropIfExists($provenance);
        }
    }

    /**
     * Rolling each migration back drops its configured table.
     *
     * @return void
     */
    public function testRollsBackByDroppingTheTables(): void
    {
        \call_user_func([self::load(self::PROOFS_MIGRATION), 'down']);
        \call_user_func([self::load(self::PROVENANCE_MIGRATION), 'down']);

        self::assertFalse(Schema::hasTable(self::PROOFS));
        self::assertFalse(Schema::hasTable(self::PROVENANCE));
    }

    /**
     * The columns of the table's primary key.
     *
     * @param  string  $table
     * @return list<list<string>>
     */
    private static function primaryColumns(string $table): array
    {
        return array_values(array_map(
            static fn (array $index): array => $index['columns'],
            array_filter(Schema::getIndexes($table), static fn (array $index): bool => $index['primary']),
        ));
    }

    /**
     * The table's other indexes, each as its name and columns.
     *
     * @param  string  $table
     * @return list<array{0: string, 1: list<string>}>
     */
    private static function secondaryIndexes(string $table): array
    {
        return array_values(array_map(
            static fn (array $index): array => [$index['name'], $index['columns']],
            array_filter(Schema::getIndexes($table), static fn (array $index): bool => !$index['primary']),
        ));
    }

    /**
     * Require a shipped anonymous-class migration file and return the resulting
     * `Migration` instance.
     *
     * @param  string  $path
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private static function load(string $path): Migration
    {
        $migration = include $path;

        if (!$migration instanceof Migration) {
            self::fail('The migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
