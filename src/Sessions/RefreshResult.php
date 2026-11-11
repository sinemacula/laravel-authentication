<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;

/**
 * The outcome of refreshing a session: the rotated pair, the session returned
 * to pending, or why the refresh was refused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshResult
{
    use HoldsARotatedSession {
        succeeded as public refreshed;
        hasSucceeded as public isRefreshed;
        returned as public pending;
    }
}
