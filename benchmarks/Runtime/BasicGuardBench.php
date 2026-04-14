<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BasicGuardBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for BasicGuard credential flows.
 *
 * Exercises HTTP Basic credential validation across valid, wrong-password, and
 * missing-user paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class BasicGuardBench
{
    /** @var ?\Benchmarks\Support\BasicGuardBenchHarness */
    private static ?BasicGuardBenchHarness $harness = null;

    /**
     * Benchmark valid HTTP Basic credentials.
     *
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1)]
    public function benchValidCredentials(): void
    {
        $this->harness()->runValidCredentials();
    }

    /**
     * Benchmark wrong-password HTTP Basic credentials.
     *
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1)]
    public function benchWrongPassword(): void
    {
        $this->harness()->runWrongPassword();
    }

    /**
     * Benchmark a nonexistent HTTP Basic identifier.
     *
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1)]
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
