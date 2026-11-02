<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\RefreshCredential;
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
     * have failed for the token's session or from the request's IP address, and
     * otherwise judges the token, its session and the session's owner; then the
     * authentication policy of the session's active tenant, judged against the
     * session's proofs and provenance: one requiring sign-in through a
     * connection the session was not established through revokes the session
     * (`tenant_policy_changed`) and refuses the refresh as `sso_required`, and
     * one asking for a further factor the session lacks returns it to pending
     * instead of rotating, the result carrying the pending session and its
     * credential and no pair, with `SessionReturnedToPending` scheduled for
     * once that is committed, and a binding of the guard to that session
     * forgotten; on success `Refreshed` and `SignedIn` (with `refresh` set) are
     * scheduled for once the rotation is committed on the session's connection,
     * and then the guard is bound to the session as a sign-in (`Validated`,
     * `Login` and the bind events). A refusal dispatches Laravel's `Failed` and
     * then `AuthenticationFailed` with the reason, and is returned, never
     * thrown, `rate_limited` included.
     *
     * The presented token is rotated before the guard is bound, so an exception
     * from a listener on `Refreshed` or on the binding events propagates after
     * the rotation and the new pair is lost; a binding listener's cannot
     * withhold `Refreshed`, which was scheduled first. A retry with the
     * presented token inside the grace window gets the current credential;
     * after the window it is treated as a replay and revokes the session.
     *
     * Only for a token a body application's own code read: a cookie
     * application's token is read only from its cookie, whose cross-site checks
     * only `refreshFromRequest()` makes, so on a cookie application this throws
     * a `LogicException`.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Throwable
     */
    public function refresh(#[\SensitiveParameter] Secret|string $refreshToken): RefreshResult
    {
        return $this->refreshes->refresh($refreshToken);
    }

    /**
     * Refresh with the refresh token the request carries, read through the
     * application's refresh token transport, so it comes by the application's
     * own transport and a cookie passes its cross-site checks.
     *
     * Returns `null`, dispatching nothing, when the request carries no token
     * (nothing was attempted). A token the transport refuses fails with its
     * reason (`refresh_token_conflict`, `refresh_transport_mismatch`,
     * `cross_site_request`, `token_invalid`) after `Attempting`, `Failed` and
     * `AuthenticationFailed`, touching no session; otherwise it is refreshed as
     * `refresh()` refreshes. The result says where the token was read from; a
     * cookie application's refreshed pair carries the cookie that sets the new
     * refresh token, never the token itself.
     *
     * @return ?\SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Throwable
     */
    public function refreshFromRequest(): ?RefreshResult
    {
        return $this->refreshes->refreshFromRequest();
    }

    /**
     * Who the refresh credential the request carries would sign in again,
     * without rotating it or binding anything: `null` when the request carries
     * none; the reason the transport, the session the token names (a replay
     * revoking it, as a refresh does), the session's owner, admitted as a
     * refresh admits it, or the tenant's authentication policy, judged as a
     * refresh judges it but writing nothing, refuses it; or the
     * `RefreshCredential` with the owner, the principal, the active tenant, the
     * session and where the credential was read from. It dispatches nothing but
     * a replay's `SessionRevoked`: its caller reports a refusal. The seam
     * `Auth::caller()` reads a refresh credential through, not a way to
     * authenticate.
     *
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential|null
     *
     * @throws \Throwable
     *
     * @internal
     */
    public function refreshCredentialFromRequest(): FailureReason|RefreshCredential|null
    {
        return $this->refreshes->credentialFromRequest();
    }
}
