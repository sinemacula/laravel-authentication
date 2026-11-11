<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Admission\Refused;

/**
 * Thrown inside a pending action's transaction to roll back a refused action;
 * `PendingSessions` catches it.
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
