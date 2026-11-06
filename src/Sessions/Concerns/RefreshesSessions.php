<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
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
     * Exchange the refresh token presented for a new access token and a rotated
     * refresh token, and bind the guard to the refreshed session.
     *
     * What was presented is what `RefreshTokenTransport::extract()` answered
     * from the request (the token, its source and the carriers the request
     * carried one in; a reason; or `null`), or a `PresentedRefreshToken` the
     * application built as its trusted description of a request it read itself
     * (`PresentedRefreshToken::fromBody()` for a token a body application read
     * from its body), with the request's `ClientContext`. Valid on a cookie and
     * a body application alike; nothing is read from the guard's request to
     * judge the token, limit the attempt, report the refresh or bind the guard.
     *
     * The package judges every fact again (`RefreshTokenTransport::judge()`): a
     * token whose carriers are not its source alone fails as
     * `refresh_token_conflict`, one whose source is not the application's
     * transport (a body token on a cookie application, the cookie on a body
     * application) as `refresh_transport_mismatch`, and one from the cookie
     * whose client fails the same-site check, as a context without its
     * `Origin`, scheme and host or custom header does, as `cross_site_request`.
     * A reason `extract()` answered (`refresh_token_conflict`,
     * `refresh_transport_mismatch`, `token_invalid`) is reported as one of
     * these is; any other is a caller's error (`InvalidArgumentException`), and
     * nothing is dispatched. A refusal here dispatches `Attempting`, `Failed`
     * and `AuthenticationFailed` and touches no session; `null` (the request
     * carried no token, so nothing was attempted) returns `null`, dispatching
     * nothing.
     *
     * Otherwise, in order: Laravel's `Attempting`; the exchange, which fails as
     * `rate_limited` (with the wait in `retryAfter`) once too many refreshes
     * have failed for the token's session or from the client's IP address (a
     * client without one is limited by the session alone), and otherwise judges
     * the token, its session and the session's owner; then the authentication
     * policy of the session's active tenant, judged against the session's
     * proofs and provenance: one requiring sign-in through a connection the
     * session was not established through revokes the session
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
     * thrown, `rate_limited` included. Every package event the refresh
     * dispatches carries the client, as do the guard's bind events
     * (`PrincipalAssigned` and `SessionAuthenticated`) and so the session's
     * last use, which `SessionAuthenticated` records; the guard keeps no
     * client, so its later events describe its own request.
     *
     * The presented token is rotated before the guard is bound, so an exception
     * from a listener on `Refreshed` or on the binding events propagates after
     * the rotation and the new pair is lost; a binding listener's cannot
     * withhold `Refreshed`, which was scheduled first. A retry with the
     * presented token inside the grace window gets the current credential;
     * after the window it is treated as a replay and revokes the session. The
     * result says where the token was presented; a cookie application's
     * refreshed pair carries the cookie that sets the new refresh token
     * (`RefreshCookie::attachTo()`), never the token itself.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ($presented is null ? null : \SineMacula\Laravel\Authentication\Sessions\RefreshResult)
     *
     * @throws \Throwable
     */
    public function refresh(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, ClientContext $client): ?RefreshResult
    {
        return $this->refreshes->refresh($presented, $client);
    }

    /**
     * Who the presented refresh credential would sign in again, without
     * rotating it or binding anything: `null` when nothing was presented; the
     * reason `extract()` answered, or the one the transport's judgement with
     * the client, the session the token names (a replay revoking it, as a
     * refresh does, reported with the client), the session's owner, admitted as
     * a refresh admits it, or the tenant's authentication policy, judged as a
     * refresh judges it but writing nothing, refuses it with; or the
     * `RefreshCredential` with the owner, the principal, the active tenant, the
     * session and where the credential was presented. It dispatches nothing but
     * a replay's `SessionRevoked`: its caller reports a refusal. The seam
     * `Auth::caller()` reads a refresh credential through, not a way to
     * authenticate.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential|null
     *
     * @throws \Throwable
     *
     * @internal
     */
    public function refreshCredential(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, ClientContext $client): FailureReason|RefreshCredential|null
    {
        return $this->refreshes->credential($presented, $client);
    }
}
