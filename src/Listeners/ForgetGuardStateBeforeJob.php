<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\AuthManager;

/**
 * Starts every queued job with the package guards signed out.
 *
 * A queue worker keeps one application for every job it runs and forgets only
 * scoped instances between them, so a guard a job bound (through `login()`,
 * `setUser()` or `actingAs()`) would still be bound, with its identity,
 * principal and device, in the next job. Before each job this resets every
 * package guard already resolved to the current request, as an HTTP request
 * does; it creates no guard and registers no rebinding callback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ForgetGuardStateBeforeJob
{
    /**
     * Handle the `JobProcessing` event, which carries nothing the reset needs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(): void
    {
        $auth = Container::getInstance()->make('auth');

        if (!$auth instanceof AuthManager) {
            return;
        }

        $auth->forgetGuardState();
    }
}
