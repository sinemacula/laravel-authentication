<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;

/**
 * The outcome of switching a session's principal, its active tenant or both:
 * the same session with its new token pair, the session returned to pending
 * when the destination's tenant asks for a further factor it lacks, or why it
 * was refused.
 *
 * A refused switch leaves the session as it was (unless the presented refresh
 * token proved a replay, which revokes the session), and `AuthenticationFailed`
 * reports why; `retryAfter` carries the wait of a `rate_limited` refusal. A
 * switch returned to pending carries the pending session and its credential,
 * which only ever goes in the response's body; the session's tokens are then
 * refused until it is satisfied. A switch with a presented refresh token says
 * where the token came from (`source`), unless a reason `extract()` answered
 * was handed in. A cookie application's switched pair carries the cookie that
 * sets the new refresh token, never the token itself.
 *
 * `switched()` makes a switch that succeeded and `isSwitched()` says whether it
 * did; `pending()` makes one returned to pending and `isPending()` says whether
 * it was; `failed()` makes a refused one and `isFailed()` says whether it was.
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
