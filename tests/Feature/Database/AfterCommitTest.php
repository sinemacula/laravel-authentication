<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for work deferred until a session's connection commits, or run
 * if it rolls back, against real transactions.
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
     * Deferred work waits for the outermost commit on the session's connection
     * and is dropped on a rollback.
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
     * Work run across models waits for every model's connection to commit and
     * is dropped when one rolls back.
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
     * Work run across models never runs once any connection rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsAcrossNoModelsConnectionOnceOneRolledBackFirst(): void
    {
        $session  = $this->record();
        $separate = new SeparateConnectionSession;
        $calls    = new \ArrayObject;
        $count    = self::counter($calls);
        $other    = DB::connection(SeparateConnectionSession::CONNECTION);

        DB::beginTransaction();
        $other->beginTransaction();

        $this->afterCommit()->runAcross([$session, $separate], $count);

        $other->rollBack();
        DB::commit();

        DB::beginTransaction();
        $other->beginTransaction();

        $this->afterCommit()->runAcross([$session, $separate], $count);

        DB::rollBack();
        $other->commit();

        self::assertCount(0, $calls);
    }

    /**
     * Work run once ended waits for the outermost transaction on each model's
     * connection to end, whether it commits or rolls back.
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
     * Under Laravel's testing transactions manager, work run once ended ignores
     * the transaction wrapping the test.
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
     * Work deferred in a nested transaction is dropped when it rolls back, even
     * if the outer one commits.
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
     * Under Laravel's testing transactions manager, deferred work ignores the
     * transaction wrapping the test.
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
     * Transactions on other connections neither delay nor cancel deferred work.
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
     * Work run on a rollback runs only when the session connection's
     * transaction rolls back.
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
     * Work run on a rollback in a nested transaction runs once when either it
     * or the outer transaction rolls back.
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
     * Work run on a rollback ignores transactions its writes were not made in.
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
     * Work defers only inside a transaction on the model's own connection.
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
     * A report that throws at a commit runs the required work that is due.
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
     * Required work rolled back with a nested transaction is not run by a
     * report that throws.
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
     * Required work that throws does not stop the rest, and the report's
     * exception is the one thrown.
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

        $exceptions = Exceptions::fake();

        self::assertSame('report', self::thrown(static fn () => DB::commit()));
        self::assertCount(1, $calls);
        self::assertSame(['work', 'nested'], array_map(static fn (\Throwable $exception): string => $exception->getMessage(), $exceptions->reported()));
    }

    /**
     * Required work that throws at its commit is thrown to the code that
     * commits, after the rest of the required work due has run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequiredWorkThatThrowsAtItsCommitIsThrownOnceTheRestDueHasRun(): void
    {
        $session    = $this->record();
        $calls      = new \ArrayObject;
        $exceptions = Exceptions::fake();

        DB::beginTransaction();

        $this->afterCommit()->runAcross([$session], self::thrower('work'));
        $this->afterCommit()->runAcross([$session], self::counter($calls));

        self::assertSame('work', self::thrown(static fn () => DB::commit()));
        self::assertCount(1, $calls);

        $exceptions->assertNothingReported();
    }

    /**
     * Work run across models still runs when the request ends after a commit
     * callback registered before it threw, and only once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsAcrossModelsWhenTheRequestEndsAfterAnEarlierCommitCallbackThrew(): void
    {
        $session = $this->record();
        $calls   = new \ArrayObject;

        DB::beginTransaction();
        DB::afterCommit(self::thrower('application'));

        $this->afterCommit()->runAcross([$session], self::counter($calls));

        self::assertSame('application', self::thrown(static fn () => DB::commit()));
        self::assertCount(0, $calls);

        app()->terminate();

        self::assertCount(1, $calls);

        app()->terminate();

        self::assertCount(1, $calls);
    }

    /**
     * Work run at its commit is not run again when the request ends, and work
     * whose transaction is still open waits for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEndOfTheRequestRunsNoWorkTwiceAndNoneStillWaiting(): void
    {
        $session = $this->record();
        $calls   = new \ArrayObject;
        $count   = self::counter($calls);

        DB::beginTransaction();

        $this->afterCommit()->runAcross([$session], $count);

        DB::commit();

        self::assertCount(1, $calls);

        DB::beginTransaction();

        $this->afterCommit()->runAcross([$session], $count);

        app()->terminate();

        self::assertCount(1, $calls);

        DB::commit();

        self::assertCount(2, $calls);

        app()->terminate();

        self::assertCount(2, $calls);
    }

    /**
     * A rollback callback that throws runs the required work that is due.
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
     * Without a transactions manager, work runs at once inside a transaction.
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
