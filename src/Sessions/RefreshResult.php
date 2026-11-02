<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;

/**
 * The outcome of refreshing a session: the same session with its rotated token
 * pair, the session returned to pending when its active tenant's authentication
 * policy now asks for a further factor it lacks, or why the refresh was
 * refused.
 *
 * A refused refresh leaves the session as it was, unless the presented refresh
 * token proved a replay, or the tenant's policy now requires sign-in through a
 * connection the session was not established through (`sso_required`), either
 * of which revokes the session (`rotation_reuse`, `tenant_policy_changed`);
 * `Failed` and `AuthenticationFailed` report why, and `retryAfter` carries the
 * wait of a `rate_limited` refusal. A refresh returned to pending carries no
 * token pair but the pending session and its credential, which only ever goes
 * in the response's body; `SessionReturnedToPending` reports it, and the
 * session's tokens are refused until it is satisfied. A refresh read from the
 * request (`refreshFromRequest()`) says where the refresh token came from
 * (`source`). A cookie application's refreshed pair carries the cookie that
 * sets the new refresh token, never the token itself.
 *
 * `refreshed()` makes a refresh that succeeded and `isRefreshed()` says whether
 * it did; `pending()` makes one returned to pending and `isPending()` says
 * whether it was; `failed()` makes a refused one and `isFailed()` says whether
 * it was.
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
