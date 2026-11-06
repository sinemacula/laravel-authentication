<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for work deferred until a session's connection commits, or run
 * if it rolls back, against real transactions on whichever engine the suite
 * runs on, and a session kept on a second connection, with the required work a
 * callback that throws runs before its exception leaves it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommit::class)]
#[CoversClass(RequiredWork::class)]
final class AfterCommitTest extends TestCase
{
    use InteractsWithSessionRecords;

    /**
     * Create the session table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createSessionRecordTable('stub_sessions');
    }

    /**
     * Drop the session table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::statement('drop table if exists stub_sessions');

        parent::tearDown();
    }

    /**
     * Outside any transaction, deferred work runs at once.
     *
     * @return void
     */
    public function testRunsAtOnceOutsideATransaction(): void
    {
        $calls = new \ArrayObject;

        $this->afterCommit()->run($this->record(), self::counter($calls));

        self::assertCount(1, $calls);
    }

    /**
     * Inside a transaction on the session's connection, deferred work waits for
     * that transaction to commit, including an outer one it is nested in, and
     * never runs when the transaction is rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWaitsForTheSessionConnectionsTransaction(): void
    {
        $session = $this->record();
        $calls   = new \ArrayObject;
        $count   = self::counter($calls);

        DB::beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->run($session, $count);

        DB::commit();

        self::assertCount(0, $calls);

        DB::commit();

        self::assertCount(1, $calls);

        DB::beginTransaction();

        $this->afterCommit()->run($session, $count);

        DB::rollBack();

        self::assertCount(1, $calls);
    }

    /**
     * Work run across models runs once the writes on each model's connection
     * have committed, in the order the models are given: at once with none
     * open; otherwise only once every transaction open on any of them has
     * committed, whichever commits first; never when one rolls back; and at
     * once with no model at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsAcrossEveryModelsConnection(): void
    {
        $session  = $this->record();
        $separate = new SeparateConnectionSession;
        $calls    = new \ArrayObject;
        $count    = self::counter($calls);

        $this->afterCommit()->runAcross([$session, $separate], $count);
        $this->afterCommit()->runAcross([], $count);

        self::assertCount(2, $calls);

        $other = DB::connection(SeparateConnectionSession::CONNECTION);

        DB::beginTransaction();
        $other->beginTransaction();

        $this->afterCommit()->runAcross([$session, $separate], $count);

        $other->commit();

        self::assertCount(2, $calls);

        DB::commit();

        self::assertCount(3, $calls);

        DB::beginTransaction();
        $other->beginTransaction();

        $this->afterCommit()->runAcross([$session, $separate], $count);

        DB::commit();

        self::assertCount(3, $calls);

        $other->commit();

        self::assertCount(4, $calls);

        $other->beginTransaction();

        $this->afterCommit()->runAcross([$session, $separate], $count);

        $other->rollBack();

        self::assertCount(4, $calls);
    }

    /**
     * Work run once transactions have ended runs, on each model's connection in
     * the order the models are given, once the outermost transaction open on it
     * ends, whether it commits or rolls back, never when a transaction nested
     * in it does, and not again for a second model on a connection whose
     * transaction just ended; at once with none open, and with no model at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsOnceTheTransactionsOnEveryModelsConnectionHaveEnded(): void
    {
        $session  = $this->record();
        $separate = new SeparateConnectionSession;
        $calls    = new \ArrayObject;
        $count    = self::counter($calls);
        $other    = DB::connection(SeparateConnectionSession::CONNECTION);

        $this->afterCommit()->runOnceEnded([$session, $separate], $count);
        $this->afterCommit()->runOnceEnded([], $count);

        self::assertCount(2, $calls);

        $other->beginTransaction();
        $other->beginTransaction();

        $this->afterCommit()->runOnceEnded([$separate], $count);

        $other->rollBack();
        $other->beginTransaction();
        $other->commit();

        self::assertCount(2, $calls);

        $other->commit();

        self::assertCount(3, $calls);

        $other->beginTransaction();

        $this->afterCommit()->runOnceEnded([$separate, $separate], $count);

        $other->rollBack();

        self::assertCount(4, $calls);

        DB::beginTransaction();
        $other->beginTransaction();

        $this->afterCommit()->runOnceEnded([$session, $separate], $count);

        DB::rollBack();

        self::assertCount(4, $calls);

        $other->rollBack();

        self::assertCount(5, $calls);
    }

    /**
     * Under the transactions manager of Laravel's testing traits, work run once
     * transactions have ended does not wait for the transaction that wraps each
     * test, only for one opened inside it, and runs when that one ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsOnceEndedIgnoringTheTransactionWrappingATest(): void
    {
        $session     = $this->record();
        $calls       = new \ArrayObject;
        $count       = self::counter($calls);
        $manager     = new TestingTransactionsManager([null]);
        $afterCommit = new AfterCommit(static fn (): TestingTransactionsManager => $manager);
        $connection  = DB::connection();

        $connection->setTransactionManager($manager);
        $connection->beginTransaction();

        try {
            $afterCommit->runOnceEnded([$session], $count);

            self::assertCount(1, $calls);

            DB::beginTransaction();

            $afterCommit->runOnceEnded([$session], $count);

            self::assertCount(1, $calls);

            DB::rollBack();

            self::assertCount(2, $calls);

            DB::beginTransaction();

            $afterCommit->runOnceEnded([$session], $count);

            DB::commit();

            self::assertCount(3, $calls);
        } finally {
            $connection->rollBack();
            $connection->setTransactionManager(app('db.transactions'));
        }
    }

    /**
     * Work deferred inside a nested transaction on the session's connection is
     * dropped when that nested transaction is rolled back, even though the
     * outer transaction it was nested in later commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDropsWorkRolledBackWithANestedTransaction(): void
    {
        $session = $this->record();
        $calls   = new \ArrayObject;

        DB::beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->run($session, self::counter($calls));

        DB::rollBack();
        DB::commit();

        self::assertCount(0, $calls);
    }

    /**
     * Under the transactions manager of Laravel's testing traits, the
     * transaction that wraps each test never commits, so it does not delay
     * deferred work; a transaction opened inside it still does, until it
     * commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testIgnoresTheTransactionWrappingATest(): void
    {
        $session     = $this->record();
        $calls       = new \ArrayObject;
        $count       = self::counter($calls);
        $manager     = new TestingTransactionsManager([null]);
        $afterCommit = new AfterCommit(static fn (): TestingTransactionsManager => $manager);
        $connection  = DB::connection();

        $connection->setTransactionManager($manager);
        $connection->beginTransaction();

        try {
            $afterCommit->run($session, $count);

            self::assertCount(1, $calls);

            DB::beginTransaction();

            $afterCommit->run($session, $count);

            self::assertCount(1, $calls);

            DB::commit();

            self::assertCount(2, $calls);
        } finally {
            $connection->rollBack();
            $connection->setTransactionManager(app('db.transactions'));
        }
    }

    /**
     * A transaction open on another connection neither delays nor cancels work
     * deferred for a session on its own connection, whether it is the only
     * transaction or opened inside one on the session's connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testIgnoresTransactionsOnOtherConnections(): void
    {
        $session = new SeparateConnectionSession;
        $calls   = new \ArrayObject;
        $count   = self::counter($calls);

        DB::beginTransaction();

        $this->afterCommit()->run($session, $count);

        self::assertCount(1, $calls);

        DB::rollBack();

        self::assertCount(1, $calls);

        $separate = DB::connection(SeparateConnectionSession::CONNECTION);

        $separate->beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->run($session, $count);

        DB::rollBack();

        self::assertCount(1, $calls);

        $separate->commit();

        self::assertCount(2, $calls);
    }

    /**
     * Work run on a rollback runs once when the session connection's
     * transaction rolls back, never when it commits, and not at all outside a
     * transaction, whose writes were committed as they were made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsOnTheRollbackOfTheSessionConnectionsTransactionOnly(): void
    {
        $session = $this->record();
        $calls   = new \ArrayObject;
        $count   = self::counter($calls);

        $this->afterCommit()->runIfRolledBack($session, $count);

        DB::beginTransaction();

        $this->afterCommit()->runIfRolledBack($session, $count);

        DB::commit();

        self::assertCount(0, $calls);

        DB::beginTransaction();

        $this->afterCommit()->runIfRolledBack($session, $count);

        self::assertCount(0, $calls);

        DB::rollBack();

        self::assertCount(1, $calls);
    }

    /**
     * Work run on a rollback inside a nested transaction runs, once, when
     * either rolls back: the nested one, or the outer one after the nested one
     * committed into it; and not when both commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsOnceOnTheRollbackOfANestedTransactionOrOfTheOneItIsNestedIn(): void
    {
        $session = $this->record();
        $calls   = new \ArrayObject;
        $count   = self::counter($calls);

        DB::beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->runIfRolledBack($session, $count);

        DB::commit();

        self::assertCount(0, $calls);

        DB::rollBack();

        self::assertCount(1, $calls);

        DB::beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->runIfRolledBack($session, $count);

        DB::rollBack();

        self::assertCount(2, $calls);

        DB::rollBack();

        self::assertCount(2, $calls);

        DB::beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->runIfRolledBack($session, $count);

        DB::commit();
        DB::commit();

        self::assertCount(2, $calls);
    }

    /**
     * Work run on a rollback ignores what it cannot have been written in: a
     * transaction open on another connection, the transaction wrapping a test
     * under the testing traits' manager, and everything without a manager.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsOnNoRollbackItsWritesWereNotMadeIn(): void
    {
        $session = $this->record();
        $calls   = new \ArrayObject;
        $count   = self::counter($calls);

        DB::beginTransaction();

        $this->afterCommit()->runIfRolledBack(new SeparateConnectionSession, $count);
        (new AfterCommit(static fn (): null => null))->runIfRolledBack($session, $count);

        DB::rollBack();

        self::assertCount(0, $calls);

        $manager     = new TestingTransactionsManager([null]);
        $afterCommit = new AfterCommit(static fn (): TestingTransactionsManager => $manager);
        $connection  = DB::connection();

        $connection->setTransactionManager($manager);
        $connection->beginTransaction();

        try {
            $afterCommit->runIfRolledBack($session, $count);
        } finally {
            $connection->rollBack();
            $connection->setTransactionManager(app('db.transactions'));
        }

        self::assertCount(0, $calls);
    }

    /**
     * It says whether work run now would wait: only while a transaction is open
     * on the model's own connection, and never without a transactions manager.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSaysWhetherWorkWouldWait(): void
    {
        $session  = $this->record();
        $separate = new SeparateConnectionSession;

        self::assertFalse($this->afterCommit()->defers($session));

        DB::beginTransaction();

        self::assertTrue($this->afterCommit()->defers($session));
        self::assertFalse($this->afterCommit()->defers($separate));
        self::assertFalse((new AfterCommit(static fn (): null => null))->defers($session));

        DB::rollBack();

        self::assertFalse($this->afterCommit()->defers($session));
    }

    /**
     * A report that throws at a commit runs the required work that is due
     * before its exception leaves the commit: work run across models or once
     * transactions have ended, registered after the report, runs once, a report
     * registered after it does not, and work still waiting for another
     * connection's transaction waits on for it. Work that already ran is not
     * run again by a later report that throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReportThatThrowsRunsTheRequiredWorkThatIsDue(): void
    {
        $session     = $this->record();
        $separate    = new SeparateConnectionSession;
        $calls       = new \ArrayObject;
        $count       = self::counter($calls);
        $other       = DB::connection(SeparateConnectionSession::CONNECTION);
        $afterCommit = $this->afterCommit();

        DB::beginTransaction();
        $other->beginTransaction();

        $afterCommit->run($session, self::thrower('report'));
        $afterCommit->runAcross([$session], $count);
        $afterCommit->runOnceEnded([$session], $count);
        $afterCommit->runAcross([$session, $separate], $count);
        $afterCommit->runOnceEnded([$separate], $count);
        $afterCommit->run($session, $count);

        self::assertSame('report', self::thrown(static fn () => DB::commit()));
        self::assertCount(2, $calls);

        $other->commit();

        self::assertCount(4, $calls);

        DB::beginTransaction();

        $afterCommit->run($session, self::thrower('later'));

        self::assertSame('later', self::thrown(static fn () => DB::commit()));
        self::assertCount(4, $calls);
    }

    /**
     * Required work held for a nested transaction that rolled back is let go
     * with it, so a report that throws at the outer commit does not run it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequiredWorkRolledBackIsNotRunByAReportThatThrows(): void
    {
        $session     = $this->record();
        $calls       = new \ArrayObject;
        $afterCommit = $this->afterCommit();

        DB::beginTransaction();
        DB::beginTransaction();

        $afterCommit->runAcross([$session], self::counter($calls));

        DB::rollBack();

        $afterCommit->run($session, self::thrower('report'));

        self::assertSame('report', self::thrown(static fn () => DB::commit()));
        self::assertCount(0, $calls);
    }

    /**
     * Required work that throws while it is run for a report that threw does
     * not keep the rest from running, the report's exception is the one thrown,
     * and work the required work's own report ran is not run twice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequiredWorkThatThrowsLetsTheRestRun(): void
    {
        $session     = $this->record();
        $calls       = new \ArrayObject;
        $afterCommit = $this->afterCommit();

        DB::beginTransaction();

        $afterCommit->run($session, self::thrower('report'));
        $afterCommit->runAcross([$session], self::thrower('work'));
        $afterCommit->runAcross([$session], static function () use ($afterCommit, $session): void {
            DB::transaction(static function () use ($afterCommit, $session): void {
                $afterCommit->run($session, self::thrower('nested'));
            });
        });
        $afterCommit->runAcross([$session], self::counter($calls));

        self::assertSame('report', self::thrown(static fn () => DB::commit()));
        self::assertCount(1, $calls);
    }

    /**
     * A callback run on a rollback that throws runs the required work that is
     * due, as one run on a commit does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARollbackCallbackThatThrowsRunsTheRequiredWorkThatIsDue(): void
    {
        $session     = $this->record();
        $calls       = new \ArrayObject;
        $afterCommit = $this->afterCommit();

        DB::beginTransaction();

        $afterCommit->runIfRolledBack($session, self::thrower('rollback'));
        $afterCommit->runOnceEnded([$session], self::counter($calls));

        self::assertSame('rollback', self::thrown(static fn () => DB::rollBack()));
        self::assertCount(1, $calls);
    }

    /**
     * Without a transactions manager, nothing can be deferred, so the work runs
     * at once even inside a transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsAtOnceWithoutATransactionsManager(): void
    {
        $session = $this->record();
        $calls   = new \ArrayObject;

        DB::beginTransaction();

        (new AfterCommit(static fn (): null => null))->run($session, self::counter($calls));

        DB::rollBack();

        self::assertCount(1, $calls);
    }

    /**
     * Add the second connection a session can be kept on.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . SeparateConnectionSession::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * Build the deferral on the application's transactions manager.
     *
     * @return \SineMacula\Laravel\Authentication\Database\AfterCommit
     */
    private function afterCommit(): AfterCommit
    {
        return new AfterCommit(static fn (): mixed => app('db.transactions'));
    }

    /**
     * A callback that records each call it receives.
     *
     * @param  \ArrayObject<int, true>  $calls
     * @return \Closure(): void
     */
    private static function counter(\ArrayObject $calls): \Closure
    {
        return static function () use ($calls): void {
            $calls->append(true);
        };
    }

    /**
     * A callback that throws a runtime exception with the message.
     *
     * @param  string  $message
     * @return \Closure(): void
     */
    private static function thrower(string $message): \Closure
    {
        return static function () use ($message): void {
            throw new \RuntimeException($message);
        };
    }

    /**
     * The message of the runtime exception the work throws.
     *
     * @param  \Closure(): mixed  $work
     * @return string
     */
    private static function thrown(\Closure $work): string
    {
        try {
            $work();
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the work to throw.');
    }

    /**
     * Persist a live session and load it back.
     *
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function record(): StubSession
    {
        $session = new StubSession;
        $session->forceFill(self::liveSession())->save();

        return StubSession::query()->findOrFail($session->id);
    }
}
