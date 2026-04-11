<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Benchmarks\Support\RefreshTokenExchangeBenchHarness;

/**
 * @Warmup(1)
 */
final class RefreshTokenExchangeBench
{
    private static ?RefreshTokenExchangeBenchHarness $harness = null;

    /**
     * @Revs(10)
     *
     * @Iterations(5)
     */
    public function benchRefreshSuccess(): void
    {
        $this->harness()->runRefreshSuccess();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     */
    public function benchUnknownDeviceFailure(): void
    {
        $this->harness()->runUnknownDeviceFailure();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     */
    public function benchRotationMismatchFailure(): void
    {
        $this->harness()->runRotationMismatchFailure();
    }

    /**
     * Lazily initialize the shared harness.
     *
     * @return \Benchmarks\Support\RefreshTokenExchangeBenchHarness
     */
    private function harness(): RefreshTokenExchangeBenchHarness
    {
        return self::$harness ??= new RefreshTokenExchangeBenchHarness;
    }
}
