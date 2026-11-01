<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;

/**
 * A proof as the session records it, read back: a snapshot, so no caller holds
 * or changes the stored row.
 *
 * The evaluation is the adapter's, for a proof an adapter verified, and `null`
 * for one this package verified itself (a first factor or a reauthentication
 * with it).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecordedProof
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  ?string  $factor
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Evaluation  $evaluation
     * @param  list<string>  $methods
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     */
    public function __construct(

        /** The proof's own id. */
        public string $id,

        /** What kind of proof it is. */
        public ProofKind $kind,

        /** What it was made for. */
        public Purpose $purpose,

        /** The method it was verified with: a sign-in method's name, or the adapter's. */
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

        /** When it was made. */
        public CarbonImmutable $authenticatedAt,
    ) {}
}
