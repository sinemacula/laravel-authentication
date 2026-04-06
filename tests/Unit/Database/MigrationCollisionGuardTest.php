<?php

declare(strict_types=1);

namespace Tests\Unit\Database;

use Illuminate\Database\Schema\Builder;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;

/**
 * MigrationCollisionGuard unit tests.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class MigrationCollisionGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Asserts the guard throws a RuntimeException when the configured
     * devices table already exists in the schema.
     *
     * @return void
     */
    public function testEnsureNotExistsThrowsWhenTableExists(): void
    {
        $schema = Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('devices')
            ->andReturn(true);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot install the laravel-authentication devices migration');
        $this->expectExceptionMessage('devices');

        $guard->ensureNotExists('devices');
    }

    /**
     * Asserts the guard returns silently when the configured devices
     * table is not present in the schema.
     *
     * @return void
     */
    public function testEnsureNotExistsSucceedsWhenTableMissing(): void
    {
        $schema = Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('devices')
            ->andReturn(false);

        $guard = new MigrationCollisionGuard($schema);

        $guard->ensureNotExists('devices');

        $this->assertTrue(true, 'ensureNotExists returned without throwing.');
    }

    /**
     * Asserts the exception message echoes a custom configurable table
     * name supplied at runtime.
     *
     * @return void
     */
    public function testEnsureNotExistsUsesCustomTableName(): void
    {
        $schema = Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('custom_devices')
            ->andReturn(true);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('custom_devices');

        $guard->ensureNotExists('custom_devices');
    }
}
