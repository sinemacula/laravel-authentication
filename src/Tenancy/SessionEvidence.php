<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;

/**
 * What a sign-in proved, held in memory before its session is written: its
 * first factor (under the id it will be recorded with), its proofs, and the
 * connection it was established through, if an external provider established
 * it. A tenant policy is judged against it at sign-in, so a sign-in with
 * nothing outstanding reads nothing more.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionEvidence
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $proofs
     * @param  ?string  $connectionId
     */
    public function __construct(

        /** The first factor the sign-in proved. */
        public RecordedProof $firstFactor,

        /** The proofs the sign-in proved, newest first. */
        public array $proofs,

        /** The connection the sign-in was established through, if any. */
        public ?string $connectionId,
    ) {}

    /**
     * The evidence of what the sign-in proved.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @return self
     */
    public static function of(SignInProof $proof): self
    {
        $firstFactor = $proof->recorded();

        return new self($firstFactor, [$firstFactor], $proof->provenance?->connectionId);
    }
}
