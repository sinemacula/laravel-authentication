<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;

/**
 * Thrown inside a confirmation's transaction when the change cannot be made
 * after its proof was accepted, so the transaction rolls back and the proof,
 * the pending change and anything else written stay as they were; the service
 * catches it and answers with the outcome. Never leaves the service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ChangeRefused extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome  $outcome
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     */
    public function __construct(

        /** What the confirmation answers. */
        public readonly IdentifierChangeOutcome $outcome,

        /** Why, for the failure event. */
        public readonly FailureReason $reason,
    ) {
        parent::__construct("The identifier change was refused: {$reason->value}.");
    }
}
