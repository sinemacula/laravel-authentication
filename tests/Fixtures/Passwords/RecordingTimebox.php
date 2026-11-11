<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passwords;

use Illuminate\Support\Timebox;

/**
 * A timebox with Laravel's semantics that records each early return and wait
 * without sleeping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingTimebox extends Timebox
{
    /** @var list<bool> For each call, whether the box ended early once its work was done. */
    public array $endedEarly = [];

    /** @var list<int> Each wait, in microseconds, the box made instead of sleeping. */
    public array $waits = [];

    /**
     * Run the callback as Laravel's timebox does, recording whether the box
     * ended early.
     *
     * @template TCallReturnType
     *
     * @param  (callable(static): TCallReturnType)  $callback
     * @param  int  $microseconds
     * @return TCallReturnType
     *
     * @throws \Throwable
     */
    #[\Override]
    public function call(callable $callback, int $microseconds)
    {
        try {
            return parent::call($callback, $microseconds);
        } finally {
            $this->endedEarly[] = $this->earlyReturn;
        }
    }

    /**
     * Record the wait instead of sleeping.
     *
     * @param  int  $microseconds
     * @return void
     */
    #[\Override]
    protected function usleep(int $microseconds): void
    {
        $this->waits[] = $microseconds;
    }
}
