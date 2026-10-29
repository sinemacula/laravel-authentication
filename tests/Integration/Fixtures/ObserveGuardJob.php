<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use SineMacula\Laravel\Authentication\Facades\Auth;

/**
 * A queued job that records who the `api` guard says is signed in when it runs,
 * under `identity` in the `observed.identity` container binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ObserveGuardJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Record the `api` guard's identity, or `null`.
     *
     * @return void
     */
    public function handle(): void
    {
        app()->instance('observed.identity', ['identity' => Auth::guard('api')->id()]);
    }
}
