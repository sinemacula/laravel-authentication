<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Benchmarks\Support\BasicGuardBenchHarness;

/**
 * PHPBench suite for BasicGuard credential flows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @Warmup(1)
 */
final class BasicGuardBench
{
    /** @var ?\Benchmarks\Support\BasicGuardBenchHarness */
    private static ?BasicGuardBenchHarness $harness = null;

    /**
     * @Revs(1)
     *
     * @Iterations(3)
     */
    public function benchValidCredentials(): void
    {
        $this->harness()->runValidCredentials();
    }

    /**
     * @Revs(1)
     *
     * @Iterations(3)
     */
    public function benchWrongPassword(): void
    {
        $this->harness()->runWrongPassword();
    }

    /**
     * @Revs(1)
     *
     * @Iterations(3)
     */
    public function benchMissingUser(): void
    {
        $this->harness()->runMissingUser();
    }

    /**
     * Lazily initialize the shared harness.
     *
     * @return \Benchmarks\Support\BasicGuardBenchHarness
     */
    private function harness(): BasicGuardBenchHarness
    {
        return self::$harness ??= new BasicGuardBenchHarness;
    }
}
