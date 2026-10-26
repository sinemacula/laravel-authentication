<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\JwtGuardBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for JwtGuard bearer-auth paths.
 *
 * Exercises the full bearer-token resolution pipeline across 2D access-only,
 * device-bearing, 3D principal, tenant-aware, and multi-guard coexistence
 * scenarios.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class JwtGuardBench
{
    /** @var ?\Benchmarks\Support\JwtGuardBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?JwtGuardBenchHarness $harness = null;

    /**
     * Benchmark 2D bearer path with no device hint.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchAccessOnlyBearer(): void
    {
        $this->harness()->runAccessOnlyBearer();
    }

    /**
     * Benchmark 2D bearer path with a warm identity cache.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchAccessOnlyBearerWarmIdentityCache(): void
    {
        $this->harness()->runAccessOnlyBearerWarmIdentityCache();
    }

    /**
     * Benchmark device-bearing bearer path when the timestamp listener skips
     * the write.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchDeviceHintNoWrite(): void
    {
        $this->harness()->runDeviceBearerNoWrite();
    }

    /**
     * Benchmark device-bearing bearer path when the listener persists
     * `last_logged_in_at`.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchDeviceHintWrite(): void
    {
        $this->harness()->runDeviceBearerWithWrite();
    }

    /**
     * Benchmark 3D principal-resolution bearer path.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchThreeDimensionalBearer(): void
    {
        $this->harness()->runThreeDimensionalBearer();
    }

    /**
     * Benchmark tenant-aware 3D bearer path.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchThreeDimensionalBearerTenantAccess(): void
    {
        $this->harness()->runThreeDimensionalBearerTenantAccess();
    }

    /**
     * Benchmark tenant-aware 3D bearer path with a secondary tenant principal.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchThreeDimensionalBearerSecondaryTenantAccess(): void
    {
        $this->harness()->runThreeDimensionalBearerSecondaryTenantAccess();
    }

    /**
     * Benchmark tenant-aware 3D bearer path with a warm identity cache.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchThreeDimensionalBearerTenantAccessWarmIdentityCache(): void
    {
        $this->harness()->runThreeDimensionalBearerTenantAccessWarmIdentityCache();
    }

    /**
     * Benchmark sequential 2D + 3D guard coexistence in one process.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchGuardCoexistenceBearer(): void
    {
        $this->harness()->runGuardCoexistenceBearer();
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
