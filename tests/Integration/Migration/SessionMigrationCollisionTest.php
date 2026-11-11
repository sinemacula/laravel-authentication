<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\TableAlreadyExistsException;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\RunsMigrationSteps;
use Tests\TestCase;

/**
 * Integration test for the sessions migration's collision guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class SessionMigrationCollisionTest extends TestCase
{
    use RunsMigrationSteps;

    /** Absolute path to the shipped sessions migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000000_create_authentication_sessions_table.php';

    /**
     * Reset the configured sessions table name and drop any sessions tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('authentication.session.table', 'authentication_sessions');

        Schema::dropIfExists('authentication_sessions');
        Schema::dropIfExists('app_sessions');
    }

    /**
     * Drop any tables created by the test so later tests see a clean
     * connection.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('authentication_sessions');
        Schema::dropIfExists('app_sessions');

        parent::tearDown();
    }

    /**
     * The migration refuses to run over an existing sessions table and names
     * the key that renames it.
     *
     * @return void
     */
    public function testMigrationThrowsRuntimeExceptionWhenSessionsTableAlreadyExists(): void
    {
        Schema::create('authentication_sessions', static function (Blueprint $blueprint): void {

            $blueprint->id();
        });

        $migration = $this->loadMigration();

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessageMatches('/Cannot install the laravel-authentication migration for the \'sessions\' table/');
        $this->expectExceptionMessageMatches('/Set `session\.table` in config\/authentication\.php/');

        self::runMigrationStep($migration);
    }

    /**
     * When the collision guard throws, the existing `authentication_sessions`
     * table is left as it was: the guard aborts before `Schema::create()`.
     *
     * @return void
     */
    public function testMigrationDoesNotMutateSchemaWhenCollisionDetected(): void
    {
        Schema::create('authentication_sessions', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('sentinel_column');
        });

        $migration = $this->loadMigration();

        try {
            self::runMigrationStep($migration);
        } catch (\RuntimeException) { // @phpstan-ignore catch.neverThrown
            // Expected - fall through to assertions below.
        }

        self::assertTrue(Schema::hasTable('authentication_sessions'));
        self::assertTrue(Schema::hasColumn('authentication_sessions', 'sentinel_column'));
        self::assertFalse(Schema::hasColumn('authentication_sessions', 'refresh_key'));
        self::assertFalse(Schema::hasColumn('authentication_sessions', 'authenticatable_type'));
    }

    /**
     * After dropping the conflicting table, re-running the migration succeeds
     * and creates the shipped `authentication_sessions` schema.
     *
     * @return void
     */
    public function testMigrationSucceedsAfterRenamingConflictingTable(): void
    {
        Schema::create('authentication_sessions', static function (Blueprint $blueprint): void {
            $blueprint->id();
        });

        Schema::dropIfExists('authentication_sessions');

        $migration = $this->loadMigration();
        self::runMigrationStep($migration);

        self::assertTrue(Schema::hasTable('authentication_sessions'));
        self::assertTrue(Schema::hasColumn('authentication_sessions', 'authenticatable_type'));
        self::assertTrue(Schema::hasColumn('authentication_sessions', 'refresh_key'));
    }

    /**
     * A custom `session.table` name routes the migration to that table.
     *
     * @return void
     */
    public function testMigrationSucceedsAgainstCustomTableNameWhenNoCollision(): void
    {
        config()->set('authentication.session.table', 'app_sessions');

        $migration = $this->loadMigration();
        self::runMigrationStep($migration);

        self::assertTrue(Schema::hasTable('app_sessions'));
        self::assertFalse(Schema::hasTable('authentication_sessions'));
        self::assertTrue(Schema::hasColumn('app_sessions', 'authenticatable_type'));
        self::assertTrue(Schema::hasColumn('app_sessions', 'refresh_key'));
    }

    /**
     * The migration names the refresh-key column after the session model,
     * ignoring any config.
     *
     * @return void
     */
    public function testMigrationCreatesRefreshKeyColumnNamedBySessionContract(): void
    {
        config()->set('authentication.session.refresh_key_column', 'renamed_refresh_key');

        $migration = $this->loadMigration();
        self::runMigrationStep($migration);

        self::assertTrue(Schema::hasColumn('authentication_sessions', (new Session)->getRefreshKeyName()));
        self::assertFalse(Schema::hasColumn('authentication_sessions', 'renamed_refresh_key'));
    }

    /**
     * Require the shipped anonymous-class migration and return it.
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
