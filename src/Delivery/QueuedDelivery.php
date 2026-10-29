<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Delivery;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Database\AfterCommit;

/**
 * Queues the package's delivery jobs, so a delivery is never part of the
 * request that asked for it: its response and timing then say nothing about
 * whether anyone receives it.
 *
 * A job is pushed with the `authentication.delivery.queue` connection and queue
 * once the writes on its anchor's connection (the row the delivery reports, a
 * code's, say) have committed, and never when they roll back. A connection that
 * would run the job during its dispatch gets it after the response instead: a
 * `sync` one runs it then, and a `failover` one that can fall back to `sync` is
 * pushed to then. No job uses Laravel's `afterCommit`, which would follow the
 * default connection's transaction rather than the anchor's.
 *
 * It keeps no state between calls: the settings, the dispatcher and the
 * transactions manager are resolved from the container each time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class QueuedDelivery
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the configuration, dispatcher, application and transactions manager are resolved from. */
        private Container $container,
    ) {}

    /**
     * The delivery settings, validated, so a caller fails closed on them before
     * it counts or writes anything.
     *
     * @return \SineMacula\Laravel\Authentication\Delivery\DeliverySettings
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function settings(): DeliverySettings
    {
        $settings = new DeliverySettings($this->container->make(Repository::class));

        $settings->validate();

        return $settings;
    }

    /**
     * Push the job once the anchor's connection commits. The job must use
     * Laravel's `Queueable`, which carries its connection and queue.
     *
     * @param  \Illuminate\Contracts\Queue\ShouldQueue  $job
     * @param  \Illuminate\Database\Eloquent\Model  $anchor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function dispatch(ShouldQueue $job, Model $anchor): void
    {
        $settings    = $this->settings();
        $synchronous = $settings->deliversSynchronously();
        $fallsBack   = $settings->fallsBackToSync();
        $container   = $this->container;

        self::route($job, $settings);

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
            ->run($anchor, static function () use ($container, $job, $synchronous, $fallsBack): void {
                $bus = $container->make(Dispatcher::class);

                match (true) {
                    $synchronous => $bus->dispatchAfterResponse($job),
                    $fallsBack   => $container->make(Application::class)->terminating(static fn (): mixed => $bus->dispatch($job)),
                    default      => $bus->dispatch($job),
                };
            });
    }

    /**
     * Set the job's connection and queue from the validated settings, and mark
     * it to dispatch before commit: the package waits for its anchor's commit
     * itself. A job that cannot carry them is refused.
     *
     * @param  \Illuminate\Contracts\Queue\ShouldQueue  $job
     * @param  \SineMacula\Laravel\Authentication\Delivery\DeliverySettings  $settings
     * @return void
     *
     * @throws \LogicException
     */
    private static function route(ShouldQueue $job, DeliverySettings $settings): void
    {
        if (!method_exists($job, 'onConnection') || !method_exists($job, 'onQueue') || !method_exists($job, 'beforeCommit')) {
            throw new \LogicException(sprintf('%s must use %s, so its connection and queue can be set.', $job::class, Queueable::class));
        }

        $job->onConnection($settings->queueConnection());
        $job->onQueue($settings->queueName());
        $job->beforeCommit();
    }
}
