<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Builder;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\TableAlreadyExistsException;

/**
 * MigrationCollisionGuard unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class MigrationCollisionGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The guard throws when the table exists, naming the table, connection and
     * configuration key.
     *
     * @return void
     */
    public function testEnsureNotExistsThrowsWhenTableExists(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('authentication_sessions')
            ->andReturn(true);

        $connection = \Mockery::mock(Connection::class);
        $connection->shouldReceive('getName')
            ->once()
            ->andReturn('testing');

        $schema->shouldReceive('getConnection')
            ->once()
            ->andReturn($connection);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage(
            'Cannot install the laravel-authentication migration for the \'authentication_sessions\' table: a table with that name already exists on connection \'testing\'.'
            . ' Set `session.table` in config/authentication.php to a different name and re-run the migration.',
        );

        $guard->ensureNotExists('authentication_sessions', 'session.table');
    }

    /**
     * The guard returns silently when the table is missing.
     *
     * @return void
     */
    public function testEnsureNotExistsSucceedsWhenTableMissing(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('authentication_sessions')
            ->andReturn(false);

        $guard = new MigrationCollisionGuard($schema);

        // Mockery checks the `->once()` expectation on tear down.
        $guard->ensureNotExists('authentication_sessions', 'session.table');
    }

    /**
     * The message names the given table and key, and the default connection
     * when the connection has no name.
     *
     * @return void
     */
    public function testEnsureNotExistsNamesTheGivenTableAndKey(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('attempt_counters')
            ->andReturn(true);

        $connection = \Mockery::mock(Connection::class);
        $connection->shouldReceive('getName')
            ->andReturnNull();

        $schema->shouldReceive('getConnection')
            ->andReturn($connection);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage('the \'attempt_counters\' table: a table with that name already exists on connection \'default\'. Set `rate_limits.table`');

        $guard->ensureNotExists('attempt_counters', 'rate_limits.table');
    }
}
