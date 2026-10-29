<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passwords;

use Illuminate\Support\Timebox;

/**
 * A timebox that records whether the work it boxed ended it early, and runs
 * that work without waiting, so a test can tell a success that returns early
 * from a failure that waits out the box.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingTimebox extends Timebox
{
    /** @var list<bool> For each call, whether the work ended the box early. */
    public array $endedEarly = [];

    /**
     * Run the callback, recording whether it ended the box early.
     *
     * @template TCallReturnType
     *
     * @param  (callable(static): TCallReturnType)  $callback
     * @param  int  $microseconds
     * @return TCallReturnType
     */
    #[\Override]
    public function call(callable $callback, int $microseconds)
    {
        $this->earlyReturn = false;

        $result = $callback($this);

        $this->endedEarly[] = $this->earlyReturn;

        return $result;
    }
}
