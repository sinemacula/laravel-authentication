<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\UpdateDeviceTimestampBenchHarness;

/**
 * PHPBench suite for device timestamp writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @Warmup(1)
 */
final class UpdateDeviceTimestampBench
{
    /** @var ?\Benchmarks\Support\UpdateDeviceTimestampBenchHarness */
    private static ?UpdateDeviceTimestampBenchHarness $harness = null;

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     *
     * @return void
     */
    public function benchWithinThrottleSkip(): void
    {
        $this->harness()->runWithinThrottleSkip();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     *
     * @return void
     */
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
