<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\PendingSignInBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for a sign-in that waits on a further factor: the sign-in
 * written pending, then satisfied with the factor's proof, which activates it.
 *
 * Each measured run is the whole path, so the attempt-limit slots the pending
 * sign-in holds are given back by its activation and the limiter never fills.
 * The password is checked with a hasher that costs next to nothing, so the
 * timings are the package's own work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class PendingSignInBench
{
    /** @var ?\Benchmarks\Support\PendingSignInBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?PendingSignInBenchHarness $harness = null;

    /**
     * Benchmark a password sign-in written pending on a further factor, and the
     * proof of that factor activating it.
     *
     * @return void
     *
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchSignInToPendingToActive(): void
    {
        $this->harness()->runSignInToPendingToActive();
    }

    /**
     * Lazily initialise the shared harness.
     *
     * @return \Benchmarks\Support\PendingSignInBenchHarness
     *
     * @throws \LogicException
     */
    private function harness(): PendingSignInBenchHarness
    {
        return self::$harness ??= new PendingSignInBenchHarness;
    }
}
