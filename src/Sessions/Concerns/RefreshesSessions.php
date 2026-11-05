<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
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
     * application's token comes only from its cookie, whose cross-site checks
     * only `refreshFromRequest()` and `refreshPresented()` make, so on a cookie
     * application this throws a `LogicException`.
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
     * Refresh with the refresh token a controller extracted from its request
     * and handed on as plain values, for a service layer that keeps HTTP out:
     * what `RefreshTokenTransport::extract()` answered (the token, its source
     * and the carriers the request carried one in; a reason; or `null`), or a
     * `PresentedRefreshToken` the application built as its trusted description
     * of the request, and the request's `ClientContext`. Valid on a cookie and
     * a body application alike; nothing is read from the guard's request to
     * judge the token or to report what this call dispatches.
     *
     * The package judges every fact again (`RefreshTokenTransport::judge()`): a
     * token whose carriers are not its source alone fails as
     * `refresh_token_conflict`, one whose source is not the application's
     * transport as `refresh_transport_mismatch`, and one from the cookie whose
     * client fails the same-site check, as a context without its `Origin`,
     * scheme and host or custom header does, as `cross_site_request`. A reason
     * `extract()` answered is reported as `refreshFromRequest()` reports it;
     * any other is a caller's error (`InvalidArgumentException`), and nothing
     * is dispatched. A refusal here dispatches `Attempting`, `Failed` and
     * `AuthenticationFailed` and touches no session; `null` returns `null`,
     * dispatching nothing.
     *
     * Otherwise the token is refreshed as `refresh()` refreshes it, with the
     * client in place of the request's: the attempt limit counts the client's
     * IP address (a client without one is limited by the token's session
     * alone), and `Refreshed`, `SignedIn`, `AuthenticationFailed`, a
     * revocation's `SessionRevoked` and a return's `SessionReturnedToPending`
     * carry it; a retry inside the grace window gets the current credential,
     * and a replay after it revokes the session. The guard's bind (`Validated`,
     * `Login` and the bind events, and the session's last use, which
     * `SessionAuthenticated` records) describes the guard's own request, as
     * every later event of the guard does. The result says where the token was
     * presented; a cookie application's refreshed pair carries the cookie that
     * sets the new refresh token (`RefreshCookie::attachTo()`), never the token
     * itself.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ($presented is null ? null : \SineMacula\Laravel\Authentication\Sessions\RefreshResult)
     *
     * @throws \Throwable
     */
    public function refreshPresented(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, ClientContext $client): ?RefreshResult
    {
        return $this->refreshes->refreshPresented($presented, $client);
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
