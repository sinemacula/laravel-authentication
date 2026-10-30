<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Delivery\DeliverySettings;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use Tests\Fixtures\Delivery\NoopDeliveryJob;
use Tests\TestCase;

/**
 * Feature tests for the package's queued deliveries: the connection and queue a
 * job is pushed with, that it waits for its anchor's connection to commit and
 * is never pushed for a rollback, and that misconfiguration fails before
 * anything is pushed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(QueuedDelivery::class)]
#[CoversClass(DeliverySettings::class)]
final class QueuedDeliveryTest extends TestCase
{
    /**
     * A job is pushed on the configured connection and queue, marked to
     * dispatch before commit (the package already waited for its own), and
     * never `afterCommit`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobIsPushedOnTheConfiguredConnectionAndQueue(): void
    {
        config()->set('queue.connections.deliveries', ['driver' => 'database']);
        config()->set('authentication.delivery.queue', ['connection' => 'deliveries', 'name' => 'mail']);

        Queue::fake();

        $job = new NoopDeliveryJob;

        self::delivery()->dispatch($job, new OneTimeCode);

        Queue::assertPushedOn('mail', NoopDeliveryJob::class, static fn (NoopDeliveryJob $pushed): bool => $pushed === $job
            && $pushed->connection                                                                                 === 'deliveries'
            && $pushed->afterCommit                                                                                === false);
    }

    /**
     * Inside a transaction on the anchor's connection, the job waits for the
     * commit, and a rollback pushes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobWaitsForItsAnchorsCommitAndNeverOutlivesARollback(): void
    {
        config()->set('queue.connections.deliveries', ['driver' => 'database']);
        config()->set('authentication.delivery.queue.connection', 'deliveries');

        Queue::fake();

        DB::transaction(static function (): void {
            self::delivery()->dispatch(new NoopDeliveryJob, new OneTimeCode);

            Queue::assertNothingPushed();
        });

        Queue::assertPushed(NoopDeliveryJob::class, 1);

        DB::beginTransaction();

        self::delivery()->dispatch(new NoopDeliveryJob, new OneTimeCode);

        DB::rollBack();

        Queue::assertPushed(NoopDeliveryJob::class, 1);
    }

    /**
     * On the `sync` connection the job is dispatched after the response, so it
     * never runs inside the call that queued it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnTheSyncConnectionTheJobRunsAfterTheResponse(): void
    {
        Bus::fake();

        self::delivery()->dispatch(new NoopDeliveryJob, new OneTimeCode);

        Bus::assertDispatchedAfterResponseTimes(NoopDeliveryJob::class, 1);
        Bus::assertNotDispatchedSync(NoopDeliveryJob::class);
    }

    /**
     * Jobs that lack one or more of the methods `Queueable` gives: none of
     * them, the queue, or the dispatch before commit.
     *
     * @return iterable<string, array{0: \Illuminate\Contracts\Queue\ShouldQueue}>
     */
    public static function provideJobsWithoutQueueable(): iterable
    {
        yield from [
            'no method' => [new class implements ShouldQueue {}],
            'no queue'  => [new class implements ShouldQueue {
                /**
                 * Accept a connection.
                 *
                 * @param  ?string  $connection
                 * @return void
                 */
                public function onConnection(?string $connection): void {}

                /**
                 * Accept a dispatch before commit.
                 *
                 * @return void
                 */
                public function beforeCommit(): void {}
            }],
            'no dispatch before commit' => [new class implements ShouldQueue {
                /**
                 * Accept a connection.
                 *
                 * @param  ?string  $connection
                 * @return void
                 */
                public function onConnection(?string $connection): void {}

                /**
                 * Accept a queue.
                 *
                 * @param  ?string  $queue
                 * @return void
                 */
                public function onQueue(?string $queue): void {}
            }],
        ];
    }

    /**
     * A job that cannot carry a connection and a queue is a misconfiguration,
     * refused before anything is pushed.
     *
     * @param  \Illuminate\Contracts\Queue\ShouldQueue  $job
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideJobsWithoutQueueable')]
    public function testAJobWithoutQueueableIsRefused(ShouldQueue $job): void
    {
        Queue::fake();

        try {
            self::delivery()->dispatch($job, new OneTimeCode);
            self::fail('A job without Queueable was dispatched.');
        } catch (\LogicException $exception) {
            self::assertSame($job::class . ' must use ' . Queueable::class . ', so its connection and queue can be set.', $exception->getMessage());
        }

        Queue::assertNothingPushed();
    }

    /**
     * Malformed settings fail closed, naming the key, from `settings()` and
     * before anything is pushed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMalformedSettingsFailBeforeAnythingIsPushed(): void
    {
        config()->set('authentication.delivery.queue.name', ['mail']);

        Queue::fake();

        try {
            self::delivery()->settings();
            self::fail('Malformed settings were accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('authentication.delivery.queue.name must be a name, or null for the default.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);

        try {
            self::delivery()->dispatch(new NoopDeliveryJob, new OneTimeCode);
        } finally {
            Queue::assertNothingPushed();
        }
    }

    /**
     * The delivery as the container builds it.
     *
     * @return \SineMacula\Laravel\Authentication\Delivery\QueuedDelivery
     */
    private static function delivery(): QueuedDelivery
    {
        return new QueuedDelivery(app());
    }
}
