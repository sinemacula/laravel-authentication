<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use Tests\Concerns\InteractsWithChangeableIdentities;
use Tests\TestCase;

/**
 * Integration tests for the identity's row lock that every transaction writing
 * an identity with its proofs takes first: one read of the row by key, locked
 * where the engine has row locks, which a second writer of the row then waits
 * on until the transaction ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityLock::class)]
final class IdentityLockTest extends TestCase
{
    use InteractsWithChangeableIdentities;

    /** @var int How long the lock is held once the other process has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the other process must have waited to show it waited on the lock. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /**
     * Create the identities table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createChangeableIdentitiesTable();
    }

    /**
     * Drop the identities table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropChangeableIdentitiesTable();

        parent::tearDown();
    }

    /**
     * `IdentityLock` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(IdentityLock::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(IdentityLock::class, $instance);
    }

    /**
     * The lock is one read of the identity's key column by its key, limited to
     * one row, with the engine's row lock (none on SQLite).
     *
     * @return void
     */
    public function testItReadsTheRowByKeyUnderALock(): void
    {
        $identity   = self::seedChangeable();
        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = [$query->sql, $query->bindings];
        });

        DB::transaction(static fn () => IdentityLock::acquire($identity));

        $grammar = DB::connection()->getQueryGrammar();
        $lock    = DB::connection()->getDriverName() === 'sqlite' ? '' : ' for update';
        $table   = $grammar->wrapTable('changeable_identities');
        $sql     = sprintf('select %s from %s where %s = ? limit 1%s', $grammar->wrap('id'), $table, $grammar->wrap('changeable_identities.id'), $lock);

        self::assertSame([[$sql, [$identity->getKey()]]], $statements);
    }

    /**
     * Another process that writes the row while the lock is held waits until
     * the transaction that took it commits.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAWriterOfTheRowWaitsForTheTransactionHoldingIt(): void
    {
        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $identity = self::seedChangeable();
        $signal   = sys_get_temp_dir() . '/identity-lock-' . bin2hex(random_bytes(8));

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            while (!is_file("{$signal}.start")) {
                usleep(5000);
            }

            $started = microtime(true);

            DB::table('changeable_identities')->where('id', $identity->getKey())->update(['password' => 'changed']);

            file_put_contents("{$signal}.waited", (string) (microtime(true) - $started));

            posix_kill(posix_getpid(), SIGKILL);

            exit(1);
        }

        DB::transaction(static function () use ($identity, $signal): void {
            IdentityLock::acquire($identity);

            touch("{$signal}.start");
            usleep(self::HOLD_MICROSECONDS);
        });

        pcntl_waitpid($pid, $status);

        $waited = (float) file_get_contents("{$signal}.waited");

        unlink("{$signal}.start");
        unlink("{$signal}.waited");

        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $waited);
        self::assertSame('changed', DB::table('changeable_identities')->value('password'));
    }
}
