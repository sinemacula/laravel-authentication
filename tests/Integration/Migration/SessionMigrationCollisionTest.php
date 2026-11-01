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
use Tests\TestCase;

/**
 * Integration test for the shipped sessions migration's collision safety guard.
 *
 * Verifies that the migration aborts with a `TableAlreadyExistsException`
 * carrying an actionable message when the configured sessions table already
 * exists on the target connection, and that the abort occurs before any schema
 * mutation. Also verifies the happy path when no collision is present.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class SessionMigrationCollisionTest extends TestCase
{
    /** Absolute path to the shipped sessions migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000000_create_authentication_sessions_table.php';

    /**
     * Ensure every test starts with the default session config and a clean
     * in-memory schema. Individual tests mutate state as required.
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
     * Running the migration when a `authentication_sessions` table already
     * exists throws a `TableAlreadyExistsException` whose message names the
     * conflicting table and the `session.table` key that renames it.
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

        $this->runMigrationUp($migration);
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
            $this->runMigrationUp($migration);
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
        $this->runMigrationUp($migration);

        self::assertTrue(Schema::hasTable('authentication_sessions'));
        self::assertTrue(Schema::hasColumn('authentication_sessions', 'authenticatable_type'));
        self::assertTrue(Schema::hasColumn('authentication_sessions', 'refresh_key'));
    }

    /**
     * Overriding `session.table` with a custom name routes the migration to
     * that table and leaves the default `authentication_sessions` table
     * uncreated.
     *
     * @return void
     */
    public function testMigrationSucceedsAgainstCustomTableNameWhenNoCollision(): void
    {
        config()->set('authentication.session.table', 'app_sessions');

        $migration = $this->loadMigration();
        $this->runMigrationUp($migration);

        self::assertTrue(Schema::hasTable('app_sessions'));
        self::assertFalse(Schema::hasTable('authentication_sessions'));
        self::assertTrue(Schema::hasColumn('app_sessions', 'authenticatable_type'));
        self::assertTrue(Schema::hasColumn('app_sessions', 'refresh_key'));
    }

    /**
     * The migration creates the refresh-key column the shipped session model
     * names through `EloquentSession::getRefreshKeyName()`. No config key
     * renames it, so a stale `refresh_key_column` setting is ignored.
     *
     * @return void
     */
    public function testMigrationCreatesRefreshKeyColumnNamedBySessionContract(): void
    {
        config()->set('authentication.session.refresh_key_column', 'renamed_refresh_key');

        $migration = $this->loadMigration();
        $this->runMigrationUp($migration);

        self::assertTrue(Schema::hasColumn('authentication_sessions', (new Session)->getRefreshKeyName()));
        self::assertFalse(Schema::hasColumn('authentication_sessions', 'renamed_refresh_key'));
    }

    /**
     * Require the shipped anonymous-class migration file and return the
     * resulting `Migration` instance. The shipped anonymous class defines
     * `up()` and `down()` directly; callers invoke via `runMigrationUp()`
     * because `up()` is not declared on the parent `Migration` class.
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

    /**
     * Invoke the migration's `up()` method without statically calling it on the
     * parent `Migration` class (which does not declare `up`).
     *
     * @param  \Illuminate\Database\Migrations\Migration  $migration
     * @return void
     */
    private function runMigrationUp(Migration $migration): void
    {
        \call_user_func([$migration, 'up']);
    }
}
