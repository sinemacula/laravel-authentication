<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;

/**
 * A queued job that records the `AuthenticationReport` under `observed.report`
 * when it runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReportAuthenticationJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Constructor.
     *
     * @param  list<string>  $guards
     */
    public function __construct(

        /** The guards to report, in order. */
        public readonly array $guards,
    ) {}

    /**
     * Record the report.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function handle(): void
    {
        app()->instance('observed.report', AuthenticationReport::of($this->guards));
    }
}
