<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\SignInBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for sign-ins through the session service.
 *
 * Exercises a password sign-in and a sign-in by a one-time code, each starting
 * a session on a new device, and the check of a one-time code on its own. The
 * password is checked with a hasher that costs next to nothing, so the timings
 * are the package's own work rather than the password hash's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class SignInBench
{
    /** @var ?\Benchmarks\Support\SignInBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?SignInBenchHarness $harness = null;

    /**
     * Benchmark a password sign-in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchPasswordSignIn(): void
    {
        $this->harness()->runPasswordSignIn();
    }

    /**
     * Benchmark a sign-in by the one-time code sent to a phone number.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchCodeSignIn(): void
    {
        $this->harness()->runCodeSignIn();
    }

    /**
     * Benchmark the check of a correct one-time code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchCodeCheck(): void
    {
        $this->harness()->runCodeCheck();
    }

    /**
     * Lazily initialize the shared harness.
     *
     * @return \Benchmarks\Support\SignInBenchHarness
     *
     * @throws \Random\RandomException
     */
    private function harness(): SignInBenchHarness
    {
        return self::$harness ??= new SignInBenchHarness;
    }
}
