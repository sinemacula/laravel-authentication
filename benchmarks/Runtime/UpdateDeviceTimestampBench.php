<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Benchmarks\Support\UpdateDeviceTimestampBenchHarness;

/**
 * @Warmup(1)
 */
final class UpdateDeviceTimestampBench
{
    private static ?UpdateDeviceTimestampBenchHarness $harness = null;

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     */
    public function benchWithinThrottleSkip(): void
    {
        $this->harness()->runWithinThrottleSkip();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
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
