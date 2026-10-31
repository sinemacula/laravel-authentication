<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;

/**
 * The outcome of switching a session to another principal: the session on the
 * same device with its new token pair, or why it was refused.
 *
 * A refused switch leaves the session as it was (unless the presented refresh
 * token proved a replay, which revokes the device), and `AuthenticationFailed`
 * reports why; `retryAfter` carries the wait of a `rate_limited` refusal. A
 * switch read from the request (`switchPrincipalFromRequest()`) says where the
 * refresh token came from (`source`), so one read from the cookie can be
 * answered with a cookie.
 *
 * `switched()` makes a switch that succeeded and `isSwitched()` says whether it
 * did; `failed()` makes a refused one and `isFailed()` says whether it was.
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
    }
}
