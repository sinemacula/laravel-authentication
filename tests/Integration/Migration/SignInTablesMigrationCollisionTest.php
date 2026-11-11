<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\TableAlreadyExistsException;
use Tests\Concerns\RunsMigrationSteps;
use Tests\TestCase;

/**
 * Integration tests for the collision guard of the sign-in table migrations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class SignInTablesMigrationCollisionTest extends TestCase
{
    use RunsMigrationSteps;

    /** @var string Directory of the shipped migrations. */
    private const string MIGRATIONS = __DIR__ . '/../../../database/migrations/';

    /** @var string Table name the tests configure instead of the default. */
    private const string RENAMED = 'renamed_sign_in_table';

    /**
     * Drop the renamed and default tables so a persistent database starts
     * clean.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ([self::RENAMED, 'rate_limits', 'one_time_codes', 'passkeys', 'passkey_challenges', 'api_keys'] as $table) {
            Schema::dropIfExists($table);
        }

        parent::tearDown();
    }

    /**
     * Rows of `[migration, configuration key, default table]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideMigrations(): iterable
    {
        yield from [
            'rate limits'        => ['2026_04_06_000002_create_rate_limits_table.php', 'rate_limits.table', 'rate_limits'],
            'one-time codes'     => ['2026_04_06_000003_create_one_time_codes_table.php', 'codes.table', 'one_time_codes'],
            'passkeys'           => ['2026_04_06_000004_create_passkeys_table.php', 'passkeys.table', 'passkeys'],
            'passkey challenges' => ['2026_04_06_000005_create_passkey_challenges_table.php', 'passkeys.challenges_table', 'passkey_challenges'],
            'api keys'           => ['2026_04_06_000006_create_api_keys_table.php', 'api_keys.table', 'api_keys'],
        ];
    }

    /**
     * Over an existing table of its configured name, the migration throws
     * naming the table and the key that renames it.
     *
     * @param  string  $file
     * @param  string  $key
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideMigrations')]
    public function testRefusesToRunOverAnExistingTable(string $file, string $key, string $table): void
    {
        self::assertTrue(Schema::hasTable($table));

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage("for the '{$table}' table");
        $this->expectExceptionMessage("Set `{$key}` in config/authentication.php");

        $this->runMigration($file);
    }

    /**
     * The refusal comes before any change: the existing table keeps exactly the
     * columns it had.
     *
     * @param  string  $file
     * @param  string  $key
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideMigrations')]
    public function testLeavesTheExistingTableAsItWas(string $file, string $key, string $table): void
    {
        unset($key);

        Schema::dropIfExists($table);
        Schema::create($table, static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('sentinel_column');
        });

        try {
            $this->runMigration($file);
        } catch (TableAlreadyExistsException) { // @phpstan-ignore catch.neverThrown
            // Expected: the assertion below checks nothing changed.
        }

        self::assertSame(['id', 'sentinel_column'], Schema::getColumnListing($table));
    }

    /**
     * Configured with another name, the migration creates that table although a
     * table of the default name exists.
     *
     * @param  string  $file
     * @param  string  $key
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideMigrations')]
    public function testRunsUnderAnotherConfiguredName(string $file, string $key, string $table): void
    {
        self::assertTrue(Schema::hasTable($table));

        config()->set('authentication.' . $key, self::RENAMED);

        $this->runMigration($file);

        self::assertTrue(Schema::hasTable(self::RENAMED));
    }

    /**
     * Run a shipped migration's `up()`.
     *
     * @param  string  $file
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function runMigration(string $file): void
    {
        $migration = include self::MIGRATIONS . $file;

        self::assertInstanceOf(Migration::class, $migration);

        self::runMigrationStep($migration);
    }
}
