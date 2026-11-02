<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;

/**
 * The factor-change gate's answer: allowed, with the fresh proof that allows it
 * and until when the session stays fresh for it, or refused, with why. It
 * reports nothing and writes nothing: the factor package reports the change it
 * makes.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorChangeVerdict
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof  $proof
     * @param  ?\Carbon\CarbonImmutable  $freshUntil
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The fresh proof that allows the change, when it is allowed. */
        public ?RecordedProof $proof,

        /** The second the session stops being fresh for the change, when it is allowed. */
        public ?CarbonImmutable $freshUntil,

        /** Why the change is refused, when it is. */
        public ?FailureReason $reason,
    ) {}

    /**
     * An allowed change.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $proof
     * @param  \Carbon\CarbonImmutable  $freshUntil
     * @return self
     */
    public static function allowed(RecordedProof $proof, CarbonImmutable $freshUntil): self
    {
        return new self($proof, $freshUntil, null);
    }

    /**
     * A refused change.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, null, $reason);
    }

    /**
     * Whether the change is allowed.
     *
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this->reason === null;
    }
}
