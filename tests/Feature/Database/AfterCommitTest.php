<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for work deferred until a session's connection commits, against
 * real transactions on whichever engine the suite runs on, and a session kept
 * on a second connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommit::class)]
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
