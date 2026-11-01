<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * Dispatched when a session is stepped up, once its new proof is committed on
 * the session's own connection: at once when that connection has no open
 * transaction, after its transaction commits otherwise, and never for a step-up
 * that is rolled back.
 *
 * The context carries the guard, the client, the identity, principal and tenant
 * the step-up admitted, the session (which keeps its key, its refresh token and
 * its deadlines) and the method the adapter verified the proof with, such as
 * `totp`; the kind says whether the proof was a further factor or a recovery
 * code.
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
