<?php

declare(strict_types = 1);

namespace Benchmarks\Proofs;

use Benchmarks\Support\BenchOutcome;
use Carbon\CarbonImmutable;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\ProofHistory;

/**
 * PHPBench suite for deriving a session's `auth_time` and `amr` from its
 * proofs' summary rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final readonly class ProofHistoryBench
{
    /** @var \SineMacula\Laravel\Authentication\Proofs\ProofHistory The history derived from in every revolution. */
    private ProofHistory $history;

    /**
     * Build the summary rows, and check that they derive what they should.
     *
     * @throws \LogicException
     */
    public function __construct()
    {
        $now  = CarbonImmutable::createStrict(2026, 4, 10, 12, 0, 0);
        $rows = [['kind' => ProofKind::FIRST_FACTOR, 'methods' => ['pwd'], 'multifactor' => false, 'additional' => false, 'accepted' => false, 'at' => $now->subDays(30)]];

        foreach (['otp', 'sms', 'hwk', 'swk', 'face', 'fpt'] as $index => $method) {
            foreach ([ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE] as $kind) {
                foreach ([true, false] as $multifactor) {
                    $rows[] = ['kind' => $kind, 'methods' => [$method], 'multifactor' => $multifactor, 'additional' => true, 'accepted' => true, 'at' => $now->subHours($index)];
                }
            }
        }

        $none = ['multifactor' => false, 'additional' => false, 'accepted' => false];

        $rows[] = ['kind' => ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'methods' => ['pwd'], ...$none, 'at' => $now->subMinute()];
        $rows[] = ['kind' => ProofKind::EXTERNAL_REAUTHENTICATION, 'methods' => [], ...$none, 'at' => $now];

        $this->history = new ProofHistory($rows);

        BenchOutcome::assert('amr derivation', $this->history->methods() === ['pwd', 'fpt', 'face', 'swk', 'hwk', 'sms', 'otp', 'mfa']);
        BenchOutcome::assert('auth_time derivation', $this->history->authenticatedAt()?->getTimestamp() === $now->getTimestamp());
    }

    /**
     * Benchmark deriving `amr`.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchMethods(): void
    {
        $this->history->methods();
    }

    /**
     * Benchmark deriving `auth_time`.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchAuthenticatedAt(): void
    {
        $this->history->authenticatedAt();
    }
}
