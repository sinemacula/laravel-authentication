<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\RefreshTokenExchangeBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for refresh-token exchange paths.
 *
 * Exercises the full refresh rotation pipeline across success, unknown-device
 * failure, rotation-mismatch failure, and tenant-aware 3D scenarios.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class RefreshTokenExchangeBench
{
    /** @var ?\Benchmarks\Support\RefreshTokenExchangeBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?RefreshTokenExchangeBenchHarness $harness = null;

    /**
     * Benchmark a successful refresh rotation.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchRefreshSuccess(): void
    {
        $this->harness()->runRefreshSuccess();
    }

    /**
     * Benchmark the unknown-device failure path.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchUnknownDeviceFailure(): void
    {
        $this->harness()->runUnknownDeviceFailure();
    }

    /**
     * Benchmark the rotation-mismatch failure path.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchRotationMismatchFailure(): void
    {
        $this->harness()->runRotationMismatchFailure();
    }

    /**
     * Benchmark tenant-aware 3D refresh exchange.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchThreeDimensionalRefreshTenantAccess(): void
    {
        $this->harness()->runThreeDimensionalRefreshTenantAccess();
    }

    /**
     * Benchmark tenant-aware 3D refresh with a secondary tenant principal.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchThreeDimensionalRefreshSecondaryTenantAccess(): void
    {
        $this->harness()->runThreeDimensionalRefreshSecondaryTenantAccess();
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
