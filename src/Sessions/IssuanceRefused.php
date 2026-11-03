<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Admission\Refused;

/**
 * Thrown inside a proof issuance's transaction when the session, judged again
 * with the proof just recorded, cannot be issued a token, so the transaction
 * rolls back and the proof is not kept; `ProofIssuance` catches it and answers
 * with the refusal. Never leaves `ProofIssuance`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IssuanceRefused extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     */
    public function __construct(

        /** The refusal the issuance answers with. */
        public readonly Refused $refused,
    ) {
        parent::__construct("The proof issuance was refused: {$refused->reason->value}.");
    }
}
