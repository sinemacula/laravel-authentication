<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Admission\Refused;

/**
 * Thrown inside a pending action's transaction when the action is refused, so
 * the transaction rolls back and nothing it wrote is kept (a proof given with
 * it included); `PendingSessions` catches it and answers with the refusal.
 * Never leaves `PendingSessions`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PendingActionRefused extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     */
    public function __construct(

        /** The refusal the pending action answers with. */
        public readonly Refused $refused,
    ) {
        parent::__construct("The pending action was refused: {$refused->reason->value}.");
    }
}
