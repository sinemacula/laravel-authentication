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
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchRefreshSuccess(): void
    {
        $this->harness()->runRefreshSuccess();
    }

    /**
     * Benchmark the unknown-session failure path.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchUnknownSessionFailure(): void
    {
        $this->harness()->runUnknownSessionFailure();
    }

    /**
     * Benchmark the rotation-mismatch failure path.
     *
     * @return void
     *
     * @throws \Random\RandomException
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
     *
     * @throws \Random\RandomException
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
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchThreeDimensionalRefreshSecondaryTenantAccess(): void
    {
        $this->harness()->runThreeDimensionalRefreshSecondaryTenantAccess();
    }

    /**
     * Lazily initialise the shared harness.
     *
     * @return \Benchmarks\Support\RefreshTokenExchangeBenchHarness
     *
     * @throws \Random\RandomException
     */
    private function harness(): RefreshTokenExchangeBenchHarness
    {
        return self::$harness ??= new RefreshTokenExchangeBenchHarness;
    }
}
