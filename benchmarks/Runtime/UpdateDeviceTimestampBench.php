<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\UpdateDeviceTimestampBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for device timestamp persistence.
 *
 * Exercises the `UpdateDeviceTimestamp` listener across the throttle-skip path
 * (fresh timestamp) and the stale-write path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class UpdateDeviceTimestampBench
{
    /** @var ?\Benchmarks\Support\UpdateDeviceTimestampBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?UpdateDeviceTimestampBenchHarness $harness = null;

    /**
     * Benchmark the throttle-skip path where the device timestamp is already
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
     * Benchmark the write path where the device timestamp is stale and must be
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
     * Lazily initialize the shared harness.
     *
     * @return \Benchmarks\Support\UpdateDeviceTimestampBenchHarness
     */
    private function harness(): UpdateDeviceTimestampBenchHarness
    {
        return self::$harness ??= new UpdateDeviceTimestampBenchHarness;
    }
}
