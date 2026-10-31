<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;

/**
 * The session service's refresh methods, which `SessionRefresh` carries out.
 *
 * They are delegations with no state of their own but the refresh; they sit in
 * a trait only so the service stays within the number of methods one class may
 * declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RefreshesSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionRefresh Exchanges refresh tokens and binds the refreshed sessions, on the guard's context. */
    private readonly SessionRefresh $refreshes;

    /**
     * Exchange a refresh token for a new access token and a rotated refresh
     * token, and bind the guard to the refreshed session.
     *
     * In order: Laravel's `Attempting`; the exchange, which fails as
     * `rate_limited` (with the wait in `retryAfter`) once too many refreshes
     * have failed for the token's device or from the request's IP address, and
     * otherwise judges the token, its device and the session's owner; on
     * success `Refreshed` and `SignedIn` (with `refresh` set) are scheduled for
     * once the rotation is committed on the device's connection, and then the
     * guard is bound to the session as a sign-in (`Validated`, `Login` and the
     * bind events). A refusal dispatches Laravel's `Failed` and then
     * `AuthenticationFailed` with the reason, and is returned, never thrown,
     * `rate_limited` included.
     *
     * The presented token is rotated before the guard is bound, so an exception
     * from a listener on `Refreshed` or on the binding events propagates after
     * the rotation and the new pair is lost; a binding listener's cannot
     * withhold `Refreshed`, which was scheduled first. A retry with the
     * presented token inside the grace window gets the current credential;
     * after the window it is treated as a replay and revokes the device.
     *
     * For a token the caller read itself; never pass it one read from the
     * refresh cookie, whose cross-site checks only `refreshFromRequest()`
     * makes.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Throwable
     */
    public function refresh(#[\SensitiveParameter] string $refreshToken): RefreshResult
    {
        return $this->refreshes->refresh($refreshToken);
    }

    /**
     * Refresh with the refresh token the request carries, read through the
     * guard's refresh token transport, so it comes from the one source the
     * guard allows and a cookie passes its cross-site checks.
     *
     * Returns `null`, dispatching nothing, when the request carries no token
     * (nothing was attempted). A token the transport refuses fails with its
     * reason (`refresh_token_conflict`, `cross_site_request`, `token_invalid`)
     * after `Attempting`, `Failed` and `AuthenticationFailed`, touching no
     * device; otherwise it is `refresh()`. The result says where the token was
     * read from, so a cookie refresh can be answered with a cookie.
     *
     * @return ?\SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Throwable
     */
    public function refreshFromRequest(): ?RefreshResult
    {
        return $this->refreshes->refreshFromRequest();
    }
}
