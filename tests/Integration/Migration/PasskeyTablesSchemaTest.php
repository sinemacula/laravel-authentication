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
 * Integration tests for the shape of the tables the shipped passkeys and
 * passkey challenges migrations create, on whichever engine the suite runs
 * against: the columns and their nullability, the index a credential is found
 * by, the owner and expiry indexes, whole-second times, a credential id of the
 * longest length WebAuthn allows, and a public key and ceremony options longer
 * than a 64 KiB text column holds.
 *
 * The migrations run for configured table names other than the defaults and
 * with the schema builder's default time precision raised, so the index names
 * and the whole-second precision are what the migrations themselves declare.
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
final class PasskeyTablesSchemaTest extends TestCase
{
    /** @var string Directory of the shipped migrations. */
    private const string MIGRATIONS = __DIR__ . '/../../../database/migrations/';

    /** @var string Configured passkeys table name the migration runs for. */
    private const string PASSKEYS = 'webauthn_credentials';

    /** @var string Configured challenges table name the migration runs for. */
    private const string CHALLENGES = 'webauthn_challenges';

    /**
     * Run the shipped migrations for the configured names, with the schema
     * builder's default time precision raised to microseconds while they run.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::dropIfExists('passkeys');
        Schema::dropIfExists('passkey_challenges');

        config()->set('authentication.passkeys.table', self::PASSKEYS);
        config()->set('authentication.passkeys.challenges_table', self::CHALLENGES);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(6);

        try {
            $this->loadMigration('2026_04_06_000004_create_passkeys_table.php')->up(); // @phpstan-ignore method.notFound
            $this->loadMigration('2026_04_06_000005_create_passkey_challenges_table.php')->up(); // @phpstan-ignore method.notFound
        } finally {
            Builder::defaultTimePrecision($precision);
        }
    }

    /**
     * Drop the tables the test migrated, through the migrations' own `down()`.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->loadMigration('2026_04_06_000004_create_passkeys_table.php')->down(); // @phpstan-ignore method.notFound
        $this->loadMigration('2026_04_06_000005_create_passkey_challenges_table.php')->down(); // @phpstan-ignore method.notFound

        parent::tearDown();
    }

    /**
     * The passkeys table holds the id, the credential id and its digest, the
     * owner, the relying party, the user handle, the public key, the count, the
     * transports, the AAGUID, the backup and verification flags, the name, and
     * the last use and timestamps; only the AAGUID, the name and the times may
     * be missing.
     *
     * @return void
     */
    public function testThePasskeysTableHasItsColumnsAndNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::PASSKEYS), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'aaguid'               => true,
            'authenticatable_id'   => false,
            'authenticatable_type' => false,
            'backup_eligible'      => false,
            'backup_state'         => false,
            'created_at'           => true,
            'credential_id'        => false,
            'credential_id_hash'   => false,
            'id'                   => false,
            'last_used_at'         => true,
            'name'                 => true,
            'public_key'           => false,
            'rp_id'                => false,
            'sign_count'           => false,
            'transports'           => false,
            'updated_at'           => true,
            'user_handle'          => false,
            'uv_initialized'       => false,
        ], $columns);
    }

    /**
     * A passkey is found by the unique digest of its credential id, and an
     * owner's passkeys of a relying party by the owner index, named after the
     * configured table.
     *
     * @return void
     */
    public function testThePasskeysTableIsIndexedForItsLookups(): void
    {
        $indexes = [];

        foreach (Schema::getIndexes(self::PASSKEYS) as $index) {
            $indexes[$index['primary'] ? 'primary' : $index['name']] = [$index['columns'], $index['unique']];
        }

        ksort($indexes);

        self::assertSame([
            'primary'                                     => [['id'], true],
            self::PASSKEYS . '_credential_id_hash_unique' => [['credential_id_hash'], true],
            self::PASSKEYS . '_owner_index'               => [['authenticatable_type', 'authenticatable_id', 'rp_id'], false],
        ], $indexes);
    }

    /**
     * The challenges table holds the id, the purpose, the guard, the relying
     * party, the owner a registration or a factor is bound to, the options, the
     * expiry and the creation time; only the owner and the creation time may be
     * missing. It is indexed on the expiry, for pruning.
     *
     * @return void
     */
    public function testTheChallengesTableHasItsColumnsAndIndexes(): void
    {
        $columns = array_column(Schema::getColumns(self::CHALLENGES), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'authenticatable_id'   => true,
            'authenticatable_type' => true,
            'created_at'           => true,
            'expires_at'           => false,
            'guard'                => false,
            'id'                   => false,
            'options'              => false,
            'purpose'              => false,
            'rp_id'                => false,
        ], $columns);

        $secondary = array_values(array_filter(Schema::getIndexes(self::CHALLENGES), static fn (array $index): bool => !$index['primary']));

        self::assertSame([[['expires_at'], self::CHALLENGES . '_expires_at_index']], array_map(static fn (array $index): array => [$index['columns'], $index['name']], $secondary));
    }

    /**
     * Every time is stored to the whole second, the precision the passkey
     * service writes and compares at.
     *
     * @return void
     */
    public function testStoresEveryTimeToTheWholeSecond(): void
    {
        foreach ([self::PASSKEYS => ['last_used_at', 'created_at', 'updated_at'], self::CHALLENGES => ['expires_at', 'created_at']] as $table => $times) {

            $types = array_column(Schema::getColumns($table), 'type', 'name');

            foreach ($times as $column) {
                self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $types[$column], "{$table}.{$column}");
            }
        }
    }

    /**
     * A credential id of the longest length WebAuthn allows (1023 bytes, 1364
     * characters in base64url) is stored in full and found by its digest, and a
     * second row with the same digest is refused by the unique index, so an
     * insert that ignores conflicts inserts nothing.
     *
     * @return void
     */
    public function testTheLongestCredentialIdIsStoredAndUnique(): void
    {
        $credentialId = rtrim(strtr(base64_encode(str_repeat("\xff", 1023)), '+/', '-_'), '=');
        $row          = [
            'id'                   => '0195f4a2-7b1c-7000-8000-000000000001',
            'credential_id_hash'   => hash('sha256', str_repeat("\xff", 1023)),
            'credential_id'        => $credentialId,
            'authenticatable_type' => 'identity',
            'authenticatable_id'   => '1',
            'rp_id'                => 'example.test',
            'user_handle'          => str_repeat('h', 43),
            'public_key'           => str_repeat('k', 1000),
            'sign_count'           => 4294967295,
            'transports'           => '["usb"]',
        ];

        self::assertSame(1364, strlen($credentialId));
        self::assertSame(1, DB::table(self::PASSKEYS)->insertOrIgnore($row));
        self::assertSame(0, DB::table(self::PASSKEYS)->insertOrIgnore(['id' => '0195f4a2-7b1c-7000-8000-000000000002'] + $row));
        self::assertSame($credentialId, DB::table(self::PASSKEYS)->where('credential_id_hash', $row['credential_id_hash'])->value('credential_id'));
        self::assertEquals(4294967295, DB::table(self::PASSKEYS)->value('sign_count'));
    }

    /**
     * A public key longer than a 64 KiB text column holds is stored and read
     * back in full by the insert that ignores conflicts, which on MySQL would
     * otherwise cut it without an error.
     *
     * @return void
     */
    public function testThePublicKeyHoldsMoreThanATextColumn(): void
    {
        $publicKey = str_repeat('k', 70000);

        self::assertSame(1, DB::table(self::PASSKEYS)->insertOrIgnore([
            'id'                   => '0195f4a2-7b1c-7000-8000-000000000004',
            'credential_id_hash'   => hash('sha256', 'credential'),
            'credential_id'        => 'Y3JlZGVudGlhbA',
            'authenticatable_type' => 'identity',
            'authenticatable_id'   => '1',
            'rp_id'                => 'example.test',
            'user_handle'          => str_repeat('h', 43),
            'public_key'           => $publicKey,
            'transports'           => '[]',
        ]));

        self::assertSame($publicKey, DB::table(self::PASSKEYS)->value('public_key'));
    }

    /**
     * Ceremony options longer than a 64 KiB text column holds are stored and
     * read back in full.
     *
     * @return void
     */
    public function testTheChallengeOptionsHoldMoreThanATextColumn(): void
    {
        $options = json_encode(['excludeCredentials' => array_fill(0, 50, ['type' => 'public-key', 'id' => str_repeat('A', 1364)])], JSON_THROW_ON_ERROR);

        self::assertGreaterThan(65535, strlen($options));

        DB::table(self::CHALLENGES)->insert([
            'id'         => '0195f4a2-7b1c-7000-8000-000000000003',
            'purpose'    => 'register',
            'guard'      => 'api',
            'rp_id'      => 'example.test',
            'options'    => $options,
            'expires_at' => '2026-04-06 12:05:00',
        ]);

        self::assertSame($options, DB::table(self::CHALLENGES)->value('options'));
    }

    /**
     * Require a shipped anonymous-class migration file and return the resulting
     * `Migration` instance.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function loadMigration(string $file): Migration
    {
        $migration = require self::MIGRATIONS . $file;

        self::assertInstanceOf(Migration::class, $migration);

        return $migration;
    }
}
