<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;

/**
 * A proof about to be recorded on a session: everything its row holds but the
 * binding, which the session it is written for gives (its owner, its guard and
 * its key).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NewProof
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  ?string  $factor
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Evaluation  $evaluation
     * @param  list<string>  $methods
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     */
    public function __construct(

        /** What kind of proof it is. */
        public ProofKind $kind,

        /** What it was made for. */
        public Purpose $purpose,

        /** The method it was verified with. */
        public string $method,

        /** The channel it was made over. */
        public Channel $channel,

        /** The adapter's reference to the factor used, if any. */
        public ?string $factor,

        /** What was observed about the authenticator. */
        public ObservedProperties $observed,

        /** What the adapter reported, for a proof an adapter verified. */
        public ?Evaluation $evaluation,

        /** The authentication method reference values it stands for. */
        public array $methods,

        /** When it was made, to the whole second. */
        public CarbonImmutable $authenticatedAt,

        /** The evidence an external provider asserted, once accepted, for an external proof. */
        public ?ExternalEvidence $evidence = null,
    ) {}

    /**
     * The proof an adapter verified, as the session records it.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $result
     * @return self
     */
    public static function fromResult(ProofResult $result): self
    {
        return new self(
            $result->kind,
            $result->binding->purpose,
            $result->method,
            $result->channel,
            $result->factor,
            $result->observed,
            $result->evaluation,
            $result->methods,
            $result->authenticatedAt,
        );
    }
}
