<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Database\CommittedReads;

/**
 * Unit tests for the isolation rule of the revocations that must find what is
 * committed now: only a caller's transaction on PostgreSQL is asked its
 * isolation level, and one whose reads see a snapshot is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CommittedReads::class)]
final class CommittedReadsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Rows of `[the driver, the transaction level]` whose reads are never asked
     * about.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideUnaskedConnections(): iterable
    {
        yield 'mysql in a transaction' => ['mysql', 1];

        yield 'sqlite in a transaction' => ['sqlite', 2];

        yield 'pgsql outside a transaction' => ['pgsql', 0];
    }

    /**
     * A connection other than PostgreSQL's, or PostgreSQL's outside a caller's
     * transaction, passes without a query.
     *
     * @param  string  $driver
     * @param  int  $level
     * @return void
     */
    #[DataProvider('provideUnaskedConnections')]
    public function testAConnectionThatSeesWhatIsCommittedIsNotAsked(string $driver, int $level): void
    {
        $connection = \Mockery::mock(Connection::class);
        $connection->allows('getDriverName')->andReturn($driver);
        $connection->allows('transactionLevel')->andReturn($level);
        $connection->expects('scalar')->never();

        CommittedReads::assert($connection, 'A link\'s revocation');
    }

    /**
     * Rows of `[the PostgreSQL isolation level]` whose reads see what is
     * committed when each is made.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCommittedLevels(): iterable
    {
        yield 'read committed' => ['read committed'];

        yield 'read uncommitted' => ['read uncommitted'];
    }

    /**
     * A caller's PostgreSQL transaction at READ COMMITTED (or READ UNCOMMITTED,
     * which PostgreSQL runs as it) passes once asked.
     *
     * @param  string  $isolation
     * @return void
     */
    #[DataProvider('provideCommittedLevels')]
    public function testAPostgresTransactionThatReadsWhatIsCommittedPasses(string $isolation): void
    {
        $connection = \Mockery::mock(Connection::class);
        $connection->allows('getDriverName')->andReturn('pgsql');
        $connection->allows('transactionLevel')->andReturn(1);
        $connection->expects('scalar')->once()->with('select current_setting(\'transaction_isolation\')')->andReturn($isolation);

        CommittedReads::assert($connection, 'A link\'s revocation');
    }

    /**
     * Rows of `[the PostgreSQL isolation level]` whose reads see the
     * transaction's first snapshot.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSnapshotLevels(): iterable
    {
        yield 'repeatable read' => ['repeatable read'];

        yield 'serializable' => ['serializable'];
    }

    /**
     * A caller's PostgreSQL transaction at REPEATABLE READ or SERIALIZABLE is
     * refused, naming the work.
     *
     * @param  string  $isolation
     * @return void
     */
    #[DataProvider('provideSnapshotLevels')]
    public function testAPostgresTransactionThatReadsASnapshotIsRefused(string $isolation): void
    {
        $connection = \Mockery::mock(Connection::class);
        $connection->allows('getDriverName')->andReturn('pgsql');
        $connection->allows('transactionLevel')->andReturn(1);
        $connection->allows('scalar')->andReturn($isolation);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A link\'s revocation must see what is committed now, so on PostgreSQL it runs at READ COMMITTED, never REPEATABLE READ or SERIALIZABLE.');

        CommittedReads::assert($connection, 'A link\'s revocation');
    }
}
