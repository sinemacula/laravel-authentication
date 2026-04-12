<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

// phpcs:disable Squiz.Commenting.FunctionComment.SpacingAfterParamName, Squiz.Commenting.FunctionComment.ParamCommentFullStop, Squiz.Commenting.FunctionComment.ParamCommentNotCapital

use Illuminate\Support\Timebox;

/**
 * Timebox variant that executes the callback immediately.
 *
 * Used by PHPBench so BasicGuard timings reflect the inner
 * credential path rather than the configured minimum
 * wall-clock budget.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 */
final class ImmediateTimebox extends Timebox
{
    /**
     * Execute the callback immediately.
     *
     * @param  callable  $callback  callback executed immediately
     * @param  int  $microseconds
     *
     * @phpstan-param callable($this): mixed $callback
     *
     * @return mixed
     */
    #[\Override]
    public function call(callable $callback, int $microseconds): mixed
    {
        unset($microseconds);

        return $callback($this);
    }

    /**
     * No-op in immediate mode.
     *
     * @return $this
     */
    #[\Override]
    public function returnEarly()
    {
        $this->earlyReturn = true;

        return $this;
    }
}
