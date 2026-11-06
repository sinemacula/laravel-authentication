<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck;
use SineMacula\Laravel\Authentication\Sessions\PendingTransitions;
use SineMacula\Laravel\Authentication\Sessions\ReturnedToPending;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;

/**
 * The session service's switch of the principal a session acts as, its active
 * tenant, or both, which `SessionSwitch` carries out on the service's guard
 * context, rotation store and revocation writer.
 *
 * They have no state of their own but the revocation writer and the pending
 * transitions a switch uses; they sit in a trait only so the service stays
 * within the number of methods one class may declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SwitchesSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\RevocationWriter Revokes the session a switch finds its refresh token replayed on. */
    private readonly RevocationWriter $switchRevocations;

    /** @var \SineMacula\Laravel\Authentication\Sessions\PendingTransitions Returns a session to pending when a switch's destination asks for a further factor. */
    private readonly PendingTransitions $transitions;

    /**
     * Switch the session the refresh token presented proves to the target:
     * another principal of its identity (in the tenant selected for it, its
     * default unless one is named), another active tenant for the principal it
     * acts as, or both, in the same session.
     *
     * What was presented is what `RefreshTokenTransport::extract()` answered
     * from the request, or a `PresentedRefreshToken` the application built as
     * its trusted description of a request it read itself
     * (`PresentedRefreshToken::fromBody()` for a body application's), with the
     * request's `ClientContext`, as `refresh()` takes them. Valid on a cookie
     * and a body application alike; nothing is read from the guard's request to
     * judge the token, limit the attempt, report the switch or bind the guard.
     * The package judges the token again as `refresh()` does
     * (`refresh_token_conflict`, `refresh_transport_mismatch`,
     * `cross_site_request`), and a reason `extract()` answered is reported as
     * one of these is; any other is a caller's error
     * (`InvalidArgumentException`), and nothing is dispatched. A refusal here
     * reports `AuthenticationFailed` (flow `switch`, with no `Attempting` or
     * `Failed`: a switch is not a sign-in) and touches no session; `null`
     * returns `null`, dispatching nothing.
     *
     * Otherwise the attempt limit counts the client's IP address and the
     * token's session, as a refresh's does. On success `PrincipalSwitched` is
     * scheduled for once the switch is committed on the session's connection
     * (at once when no transaction is open there), and then, once it commits
     * too, as `DeferredBind` binds, the guard is bound to the session as the
     * destination principal in the destination tenant (`Authenticated`,
     * `PrincipalAssigned`, `SessionAuthenticated`, no `Login`); a bind listener
     * that throws cannot withhold the switch's report, and a switch inside a
     * transaction that rolls back binds nothing. A switch to the principal and
     * tenant the session already records rotates the credential like a refresh
     * and reports no switch. A destination whose tenant's authentication policy
     * asks for a further factor the session lacks returns the session to
     * pending with the destination recorded (`SessionReturnedToPending`): the
     * result carries the pending session and its credential, binds nothing, and
     * forgets a binding to that session. A refused switch reports
     * `AuthenticationFailed` (flow `switch`) and leaves the session as it was,
     * unless the token proved a replay, which revokes the session
     * (`SessionRevoked`, `rotation_reuse`). Every package event the switch
     * dispatches carries the client, as do the guard's bind events and so the
     * session's last use; the guard keeps no client, so its later events
     * describe its own request. A switched session's new pair is delivered as
     * the application's transport says: a cookie application's refresh token
     * only in its cookie (`RefreshCookie::attachTo()`). A retry inside the
     * grace window gets the current credential. The result says where the token
     * was presented.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ($presented is null ? null : \SineMacula\Laravel\Authentication\Sessions\SwitchResult)
     *
     * @throws \Throwable
     */
    public function switchTo(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, SwitchTarget $target, ClientContext $client): ?SwitchResult
    {
        $transport = $this->transport();

        if ($presented instanceof FailureReason) {
            return $this->refuseSwitch(SessionRefresh::handedIn($presented), $client);
        }

        if ($presented === null) {
            return null;
        }

        $refusal = $transport->judge($presented, $client);
        $result  = $refusal === null ? $this->switchWith($presented->token, $target, $transport, $client) : $this->refuseSwitch($refusal, $client);

        return $result->withSource($presented->source);
    }

    /**
     * Report a refresh token refused before the switch read any session, and
     * answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     */
    private function refuseSwitch(FailureReason $reason, ClientContext $client): SwitchResult
    {
        $this->context->dispatch(new AuthenticationFailed(new EventContext($this->context->name(), $client), AuthenticationFlow::SWITCH, $reason));

        return SwitchResult::failed($reason);
    }

    /**
     * Switch the session the refresh token proves to the target for the client,
     * and deliver the switched session's pair through the transport.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switchWith(#[\SensitiveParameter] Secret $refreshToken, SwitchTarget $target, RefreshTokenTransport $transport, ClientContext $client): SwitchResult
    {
        $began   = CarbonImmutable::now()->startOfSecond();
        $recheck = $this->recheck($client, $began);
        $revoke  = function (EloquentSession&Model $record, CarbonImmutable $now) use ($client): bool {

            $event = new SessionRevoked(
                new EventContext($record->getGuard(), $client, session: $record, method: $record->getSignInMethod(), fromSession: true),
                RevocationReason::ROTATION_REUSE,
            );

            return $this->switchRevocations->revoke($record, RevocationReason::ROTATION_REUSE, $now, fn () => $this->context->dispatch($event));
        };

        $outcome = (new SessionSwitch($this->tokens, $this->rotations, $this->context, $client, $target, $revoke, $this->transitions->forClient($client), $recheck))
            ->switch($refreshToken);
        $refusal = $recheck->refusal();

        if ($refusal !== null) {
            $outcome = new AuthenticationFailed(
                new EventContext(
                    $this->context->name(),
                    $client,
                    $refusal->identity,
                    $refusal->principal,
                    $refusal->tenant,
                    $refusal->session,
                    $refusal->session?->getSignInMethod(),
                ),
                AuthenticationFlow::SWITCH,
                $refusal->reason,
            );
        }

        if ($outcome instanceof AuthenticationFailed) {

            $this->context->dispatch($outcome);

            return SwitchResult::failed($outcome->reason, $outcome->retryAfter);
        }

        if ($outcome instanceof ReturnedToPending) {

            $this->binding->forgetSession($outcome->pending->session);

            return SwitchResult::pending($outcome->pending, $outcome->credential);
        }

        return $this->switched($outcome, $recheck, $transport);
    }

    /**
     * Report the switch once committed, and once the principal and tenant it
     * moved the session to are checked again (`AdmissionRecheck`), when the
     * principal or the tenant changed, then bind the guard to the switched
     * session in its destination tenant once it commits too, and answer it, its
     * pair delivered at once. The report is scheduled before the bind, so a
     * bind listener that throws cannot withhold it from the switch it already
     * wrote. The bind's events, and so the session's last use, describe the
     * client the switch was for.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal  $switched
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switched(SwitchedPrincipal $switched, AdmissionRecheck $recheck, RefreshTokenTransport $transport): SwitchResult
    {
        $session = $switched->session;
        $client  = $recheck->client;

        if ($switched->changed()) {

            $event = new PrincipalSwitched(
                new EventContext($this->context->name(), $client, $session->identity, $session->principal, $session->tenant, $session->record, $session->method),
                $switched->previousType,
                $switched->previousId,
                $switched->previousTenantId,
                $switched->principalChanged,
                $switched->tenantChanged,
            );

            $recheck->then($session->record, fn () => $this->context->dispatch($event));
        }

        $tokens = $transport->deliver($session->tokens, $session->record);

        $this->binds->run(
            $session->record,
            $session->principal,
            fn () => $this->binding->authenticateAs($session->identity, $session->principal, $session->record, null, $session->tenant, $client),
        );

        return SwitchResult::switched(new SignedInSession($session->identity, $session->principal, $session->record, $tokens, (string) $session->method));
    }
}
