<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Support\Timebox;

/**
 * Timebox variant that executes the callback immediately.
 *
 * Used by PHPBench so BasicGuard timings reflect the inner credential path
 * rather than the configured minimum wall-clock budget.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ImmediateTimebox extends Timebox
{
    /**
     * Execute the callback immediately.
     *
     * @param  callable  $callback
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
    public function returnEarly(): self
    {
        $this->earlyReturn = true;

        return $this;
    }
}
