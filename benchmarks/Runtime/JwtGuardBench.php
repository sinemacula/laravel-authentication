<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Benchmarks\Support\JwtGuardBenchHarness;

/**
 * @Warmup(1)
 */
final class JwtGuardBench
{
    private static ?JwtGuardBenchHarness $harness = null;

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     */
    public function benchAccessOnlyBearer(): void
    {
        $this->harness()->runAccessOnlyBearer();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     */
    public function benchDeviceHintNoWrite(): void
    {
        $this->harness()->runDeviceBearerNoWrite();
    }

    /**
     * @Revs(10)
     *
     * @Iterations(5)
     */
    public function benchDeviceHintWrite(): void
    {
        $this->harness()->runDeviceBearerWithWrite();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     */
    public function benchThreeDimensionalBearer(): void
    {
        $this->harness()->runThreeDimensionalBearer();
    }

    /**
     * Lazily initialize the shared harness.
     *
     * @return \Benchmarks\Support\JwtGuardBenchHarness
     */
    private function harness(): JwtGuardBenchHarness
    {
        return self::$harness ??= new JwtGuardBenchHarness;
    }
}
