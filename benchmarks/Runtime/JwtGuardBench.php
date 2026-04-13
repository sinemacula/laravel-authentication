<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

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
     *
     * @return void
     */
    public function benchAccessOnlyBearer(): void
    {
        $this->harness()->runAccessOnlyBearer();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     *
     * @return void
     */
    public function benchAccessOnlyBearerWarmIdentityCache(): void
    {
        $this->harness()->runAccessOnlyBearerWarmIdentityCache();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     *
     * @return void
     */
    public function benchDeviceHintNoWrite(): void
    {
        $this->harness()->runDeviceBearerNoWrite();
    }

    /**
     * @Revs(10)
     *
     * @Iterations(5)
     *
     * @return void
     */
    public function benchDeviceHintWrite(): void
    {
        $this->harness()->runDeviceBearerWithWrite();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     *
     * @return void
     */
    public function benchThreeDimensionalBearer(): void
    {
        $this->harness()->runThreeDimensionalBearer();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     *
     * @return void
     */
    public function benchThreeDimensionalBearerTenantAccess(): void
    {
        $this->harness()->runThreeDimensionalBearerTenantAccess();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     *
     * @return void
     */
    public function benchThreeDimensionalBearerSecondaryTenantAccess(): void
    {
        $this->harness()->runThreeDimensionalBearerSecondaryTenantAccess();
    }

    /**
     * @Revs(25)
     *
     * @Iterations(5)
     *
     * @return void
     */
    public function benchThreeDimensionalBearerTenantAccessWarmIdentityCache(): void
    {
        $this->harness()->runThreeDimensionalBearerTenantAccessWarmIdentityCache();
    }

    /**
     * @Revs(10)
     *
     * @Iterations(5)
     *
     * @return void
     */
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
