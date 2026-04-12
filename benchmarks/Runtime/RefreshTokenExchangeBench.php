<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Benchmarks\Support\RefreshTokenExchangeBenchHarness;

/**
 * PHPBench suite for refresh-token exchange paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @Warmup(1)
 */
final class RefreshTokenExchangeBench
{
    /** @var ?\Benchmarks\Support\RefreshTokenExchangeBenchHarness */
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
