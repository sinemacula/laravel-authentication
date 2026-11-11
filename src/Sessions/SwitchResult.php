<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;

/**
 * The outcome of switching a session's principal, active tenant or both: the
 * new pair, the session returned to pending, or why it was refused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SwitchResult
{
    use HoldsARotatedSession {
        succeeded as public switched;
        hasSucceeded as public isSwitched;
        returned as public pending;
    }
}
