<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use Tests\TestCase;

/**
 * Integration test for the shipped devices migration's collision
 * safety guard.
 *
 * Verifies that the migration aborts with a `\RuntimeException`
 * carrying an actionable message when the configured devices table
 * already exists on the target connection, and that the abort occurs
 * before any schema mutation (REQ-13 / AC-13). Also verifies the
 * happy path when no collision is present.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class DeviceMigrationCollisionTest extends TestCase
{
    /** Absolute path to the shipped devices migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000000_create_devices_table.php';

    /**
     * Ensure every test starts with the default device config and a
     * clean in-memory schema. Individual tests mutate state as
     * required.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('authentication.device.table', 'devices');
        config()->set('authentication.device.refresh_key_column', 'refresh_key');

        Schema::dropIfExists('devices');
        Schema::dropIfExists('app_devices');
    }

    /**
     * Drop any tables created by the test so later tests see a clean
     * connection.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('devices');
        Schema::dropIfExists('app_devices');

        parent::tearDown();
    }

    /**
     * Running the migration when a `devices` table already exists
     * throws a `\RuntimeException` whose message contains the
     * documented actionable substring and the conflicting table name.
     *
     * @return void
     */
    public function testMigrationThrowsRuntimeExceptionWhenDevicesTableAlreadyExists(): void
    {
        Schema::create('devices', static function (Blueprint $blueprint): void {

            $blueprint->id();
        });

        $migration = $this->loadMigration();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/Cannot install the laravel-authentication devices migration/');
        $this->expectExceptionMessageMatches('/\'devices\'/');

        $this->runMigrationUp($migration);
    }

    /**
     * When the collision guard throws, the pre-existing `devices`
     * table remains untouched - specifically, the sentinel column
     * seeded before the throw is still present, proving the abort
     * happened before `Schema::create(...)` could mutate the schema.
     *
     * @return void
     */
    public function testMigrationDoesNotMutateSchemaWhenCollisionDetected(): void
    {
        Schema::create('devices', static function (Blueprint $blueprint): void {

            $blueprint->id();
            $blueprint->string('sentinel_column');
        });

        $migration = $this->loadMigration();

        try {
            $this->runMigrationUp($migration);
        } catch (\RuntimeException) {

            // Expected - fall through to assertions below.
        }

        self::assertTrue(Schema::hasTable('devices'));
        self::assertTrue(Schema::hasColumn('devices', 'sentinel_column'));
        self::assertFalse(Schema::hasColumn('devices', 'refresh_key'));
        self::assertFalse(Schema::hasColumn('devices', 'authenticatable_type'));
    }

    /**
     * After dropping the conflicting table, re-running the migration
     * succeeds and creates the shipped `devices` schema.
     *
     * @return void
     */
    public function testMigrationSucceedsAfterRenamingConflictingTable(): void
    {
        Schema::create('devices', static function (Blueprint $blueprint): void {

            $blueprint->id();
        });

        Schema::dropIfExists('devices');

        $migration = $this->loadMigration();
        $this->runMigrationUp($migration);

        self::assertTrue(Schema::hasTable('devices'));
        self::assertTrue(Schema::hasColumn('devices', 'authenticatable_type'));
        self::assertTrue(Schema::hasColumn('devices', 'refresh_key'));
    }

    /**
     * Overriding `device.table` with a custom name routes the
     * migration to that table and leaves the default `devices` table
     * uncreated.
     *
     * @return void
     */
    public function testMigrationSucceedsAgainstCustomTableNameWhenNoCollision(): void
    {
        config()->set('authentication.device.table', 'app_devices');

        $migration = $this->loadMigration();
        $this->runMigrationUp($migration);

        self::assertTrue(Schema::hasTable('app_devices'));
        self::assertFalse(Schema::hasTable('devices'));
        self::assertTrue(Schema::hasColumn('app_devices', 'authenticatable_type'));
        self::assertTrue(Schema::hasColumn('app_devices', 'refresh_key'));
    }

    /**
     * Require the shipped anonymous-class migration file and return
     * the resulting `Migration` instance. The shipped anonymous class
     * defines `up()` and `down()` directly; callers invoke via
     * `runMigrationUp()` because `up()` is not declared on the parent
     * `Migration` class.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private function loadMigration(): Migration
    {
        $migration = include self::MIGRATION_PATH;  // NOSONAR

        if (!$migration instanceof Migration) {
            self::fail('Devices migration file did not return a Migration instance.');
        }

        return $migration;
    }

    /**
     * Invoke the migration's `up()` method without statically calling
     * it on the parent `Migration` class (which does not declare `up`).
     *
     * @param  \Illuminate\Database\Migrations\Migration  $migration
     * @return void
     */
    private function runMigrationUp(Migration $migration): void
    {
        \call_user_func([$migration, 'up']);
    }
}
