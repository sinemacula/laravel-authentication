<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Container\Container;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;
use SineMacula\Laravel\Authentication\AuthManager;

/**
 * Starts every queued job with the package guards signed out, leaving `sync`
 * jobs to the request that dispatched them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ForgetGuardStateBeforeJob
{
    /**
     * Handle the `JobProcessing` event.
     *
     * @param  \Illuminate\Queue\Events\JobProcessing  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(JobProcessing $event): void
    {
        if ($event->job instanceof SyncJob) {
            return;
        }

        $auth = Container::getInstance()->make('auth');

        if (!$auth instanceof AuthManager) {
            return;
        }

        $auth->forgetGuardState();
    }
}
