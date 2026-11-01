<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\RecordSessionUsageBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for session timestamp persistence.
 *
 * Exercises the `RecordSessionUsage` listener across the throttle-skip path
 * (fresh timestamp) and the stale-write path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class RecordSessionUsageBench
{
    /** @var ?\Benchmarks\Support\RecordSessionUsageBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?RecordSessionUsageBenchHarness $harness = null;

    /**
     * Benchmark the throttle-skip path where the session timestamp is already
     * fresh.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchWithinThrottleSkip(): void
    {
        $this->harness()->runWithinThrottleSkip();
    }

    /**
     * Benchmark the write path where the session timestamp is stale and must be
     * persisted.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchStaleTimestampWrite(): void
    {
        $this->harness()->runStaleTimestampWrite();
    }

    /**
     * Lazily initialise the shared harness.
     *
     * @return \Benchmarks\Support\RecordSessionUsageBenchHarness
     */
    private function harness(): RecordSessionUsageBenchHarness
    {
        return self::$harness ??= new RecordSessionUsageBenchHarness;
    }
}
