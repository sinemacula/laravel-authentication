<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Thrown when a reset's proof was accepted for no identity that may reset, so
 * the transaction rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResetRefused extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     */
    public function __construct(

        /** Why no identity may use the accepted proof, for the report. */
        public readonly FailureReason $reason,
    ) {
        parent::__construct("The password reset was refused: {$reason->value}.");
    }
}
