<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * Dispatched once a session's step-up proof is committed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SteppedUp extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     */
    public function __construct(

        // The stepped-up session, its guard, and whose it is.
        EventContext $context,

        /** The kind of proof the session was stepped up with. */
        public ProofKind $kind,
    ) {
        parent::__construct($context);
    }
}
