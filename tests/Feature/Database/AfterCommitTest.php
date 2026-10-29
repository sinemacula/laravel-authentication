<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;
use Tests\Unit\Stubs\StubDevice;

/**
 * Feature tests for work deferred until a device's connection commits, against
 * real transactions on whichever engine the suite runs on, and a device kept on
 * a second connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommit::class)]
final class AfterCommitTest extends TestCase
{
    use InteractsWithDevices;

    /**
     * Create the device table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createDeviceTable('stub_devices');
    }

    /**
     * Drop the device table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::statement('drop table if exists stub_devices');

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

        $this->afterCommit()->run($this->device(), self::counter($calls));

        self::assertCount(1, $calls);
    }

    /**
     * Inside a transaction on the device's connection, deferred work waits for
     * that transaction to commit, including an outer one it is nested in, and
     * never runs when the transaction is rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWaitsForTheDeviceConnectionsTransaction(): void
    {
        $device = $this->device();
        $calls  = new \ArrayObject;
        $count  = self::counter($calls);

        DB::beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->run($device, $count);

        DB::commit();

        self::assertCount(0, $calls);

        DB::commit();

        self::assertCount(1, $calls);

        DB::beginTransaction();

        $this->afterCommit()->run($device, $count);

        DB::rollBack();

        self::assertCount(1, $calls);
    }

    /**
     * Work deferred inside a nested transaction on the device's connection is
     * dropped when that nested transaction is rolled back, even though the
     * outer transaction it was nested in later commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDropsWorkRolledBackWithANestedTransaction(): void
    {
        $device = $this->device();
        $calls  = new \ArrayObject;

        DB::beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->run($device, self::counter($calls));

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
        $device      = $this->device();
        $calls       = new \ArrayObject;
        $count       = self::counter($calls);
        $manager     = new TestingTransactionsManager([null]);
        $afterCommit = new AfterCommit(static fn (): TestingTransactionsManager => $manager);
        $connection  = DB::connection();

        $connection->setTransactionManager($manager);
        $connection->beginTransaction();

        try {
            $afterCommit->run($device, $count);

            self::assertCount(1, $calls);

            DB::beginTransaction();

            $afterCommit->run($device, $count);

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
     * deferred for a device on its own connection, whether it is the only
     * transaction or opened inside one on the device's connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testIgnoresTransactionsOnOtherConnections(): void
    {
        $device = new SeparateConnectionDevice;
        $calls  = new \ArrayObject;
        $count  = self::counter($calls);

        DB::beginTransaction();

        $this->afterCommit()->run($device, $count);

        self::assertCount(1, $calls);

        DB::rollBack();

        self::assertCount(1, $calls);

        $separate = DB::connection(SeparateConnectionDevice::CONNECTION);

        $separate->beginTransaction();
        DB::beginTransaction();

        $this->afterCommit()->run($device, $count);

        DB::rollBack();

        self::assertCount(1, $calls);

        $separate->commit();

        self::assertCount(2, $calls);
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
        $device = $this->device();
        $calls  = new \ArrayObject;

        DB::beginTransaction();

        (new AfterCommit(static fn (): null => null))->run($device, self::counter($calls));

        DB::rollBack();

        self::assertCount(1, $calls);
    }

    /**
     * Add the second connection a device can be kept on.
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

        $config->set('database.connections.' . SeparateConnectionDevice::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
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
     * Persist a live device and load it back.
     *
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function device(): StubDevice
    {
        $device = new StubDevice;
        $device->forceFill(self::liveSession())->save();

        return StubDevice::query()->findOrFail($device->id);
    }
}
