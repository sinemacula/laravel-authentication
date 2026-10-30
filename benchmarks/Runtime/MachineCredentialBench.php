<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\MachineCredentialBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for machine credential requests.
 *
 * Exercises the `api_key` guard authenticating a request (a key used within the
 * last-use throttle, a key recording its first use, and a wrong secret) and the
 * `jwt` guard authenticating a client credentials access token, which it checks
 * against the API key the token names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class MachineCredentialBench
{
    /** @var ?\Benchmarks\Support\MachineCredentialBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?MachineCredentialBenchHarness $harness = null;

    /**
     * Benchmark an `api_key` request whose key was used within the throttle, so
     * nothing is written.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchApiKeyRequest(): void
    {
        $this->harness()->runUsedKey();
    }

    /**
     * Benchmark an `api_key` request whose key records its first use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(10)]
    public function benchApiKeyRequestRecordingUse(): void
    {
        $this->harness()->runUnusedKey();
    }

    /**
     * Benchmark an `api_key` request refused for a wrong secret.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchApiKeyRequestRefused(): void
    {
        $this->harness()->runRefusedKey();
    }

    /**
     * Benchmark a `jwt` request bearing a client credentials access token.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchClientCredentialsBearer(): void
    {
        $this->harness()->runClientCredentialsBearer();
    }

    /**
     * Lazily initialize the shared harness.
     *
     * @return \Benchmarks\Support\MachineCredentialBenchHarness
     *
     * @throws \Random\RandomException
     */
    private function harness(): MachineCredentialBenchHarness
    {
        return self::$harness ??= new MachineCredentialBenchHarness;
    }
}
