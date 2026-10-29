<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passwords;

use Illuminate\Support\Timebox;

/**
 * A timebox with Laravel's own semantics that records, for each call, whether
 * the box ended early once its work was done, and each wait it would have made,
 * without sleeping: a test can tell a success that returns early from a failure
 * that waits out the box, however many calls one guard makes.
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
