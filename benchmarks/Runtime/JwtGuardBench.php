<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Benchmarks\Support\JwtGuardBenchHarness;

/**
 * PHPBench suite for JwtGuard bearer-auth paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @Warmup(1)
 */
final class JwtGuardBench
{
    /** @var ?\Benchmarks\Support\JwtGuardBenchHarness */
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
    public function benchAccessOnlyBearerWarmIdentityCache(): void
    {
        $this->harness()->runAccessOnlyBearerWarmIdentityCache();
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
