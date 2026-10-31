<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;

/**
 * The outcome of refreshing a session: the session on the same device with its
 * rotated token pair, or why the refresh was refused.
 *
 * A refused refresh leaves the session as it was (unless the presented refresh
 * token proved a replay, which revokes the device), and `Failed` and
 * `AuthenticationFailed` report why; `retryAfter` carries the wait of a
 * `rate_limited` refusal. A refresh read from the request
 * (`refreshFromRequest()`) says where the refresh token came from (`source`),
 * so one read from the cookie can be answered with a cookie.
 *
 * `refreshed()` makes a refresh that succeeded and `isRefreshed()` says whether
 * it did; `failed()` makes a refused one and `isFailed()` says whether it was.
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
    }
}
