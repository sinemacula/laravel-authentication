<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
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
     * Switch the session the refresh token proves to the target: another
     * principal of its identity (in the tenant selected for it, its default
     * unless one is named), another active tenant for the principal it acts as,
     * or both, in the same session.
     *
     * On success `PrincipalSwitched` is scheduled for once the switch is
     * committed on the session's connection (at once when no transaction is
     * open there), and then, once it commits too, as `DeferredBind` binds, the
     * guard is bound to the session as the destination principal in the
     * destination tenant (`Authenticated`, `PrincipalAssigned`,
     * `SessionAuthenticated`, no `Login`); a bind listener that throws cannot
     * withhold the switch's report, and a switch inside a transaction that
     * rolls back binds nothing. A switch to the principal and tenant the
     * session already records rotates the credential like a refresh and reports
     * no switch. A destination whose tenant's authentication policy asks for a
     * further factor the session lacks returns the session to pending with the
     * destination recorded: the result carries the pending session and its
     * credential, binds nothing, and forgets a binding to that session. A
     * refused switch reports `AuthenticationFailed` (flow `switch`) and leaves
     * the session as it was, unless the token proved a replay, which revokes
     * the session.
     *
     * For a body application only: a cookie application's refresh token is read
     * from its cookie, with the cookie's cross-site checks, by
     * `switchFromRequest()` alone, so a token handed in here is a
     * misconfiguration (`LogicException`). A switched session's new pair is
     * delivered as the application's transport says: a cookie application's
     * refresh token only in its cookie.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    public function switchTo(#[\SensitiveParameter] Secret|string $refreshToken, SwitchTarget $target): SwitchResult
    {
        $transport = $this->transport();

        SessionRefresh::refuseHandedIn($transport);

        return $this->switchWith($refreshToken, $target, $transport);
    }

    /**
     * Switch the session to the target with the refresh token the request
     * carries, read through the application's refresh token transport, so it
     * comes by the application's own transport and a cookie passes its
     * cross-site checks, as `refreshFromRequest()` reads one.
     *
     * Returns `null`, dispatching nothing, when the request carries no token. A
     * token the transport refuses fails with its reason
     * (`refresh_token_conflict`, `refresh_transport_mismatch`,
     * `cross_site_request`, `token_invalid`) after `AuthenticationFailed` (flow
     * `switch`), touching no session; otherwise it is switched as `switchTo()`
     * switches. The result says where the token was read from.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    public function switchFromRequest(SwitchTarget $target): ?SwitchResult
    {
        $request   = $this->context->request();
        $transport = $this->transport();
        $presented = $transport->read($request);

        if ($presented instanceof PresentedRefreshToken) {
            return $this->switchWith($presented->token, $target, $transport)->withSource($presented->source);
        }

        if ($presented !== null) {

            $context = new EventContext($this->context->name(), ClientContext::fromRequest($request));

            $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::SWITCH, $presented));

            return SwitchResult::failed($presented);
        }

        return null;
    }

    /**
     * Switch the session the refresh token proves to the target, and deliver
     * the switched session's pair through the transport.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switchWith(#[\SensitiveParameter] Secret|string $refreshToken, SwitchTarget $target, RefreshTokenTransport $transport): SwitchResult
    {
        $began   = CarbonImmutable::now()->startOfSecond();
        $client  = $this->context->client();
        $recheck = $this->recheck($client, $began);
        $revoke  = function (EloquentSession&Model $record, CarbonImmutable $now) use ($client): bool {

            $event = new SessionRevoked(
                new EventContext($record->getGuard(), $client, session: $record, method: $record->getSignInMethod(), fromSession: true),
                RevocationReason::ROTATION_REUSE,
            );

            return $this->switchRevocations->revoke($record, RevocationReason::ROTATION_REUSE, $now, fn () => $this->context->dispatch($event));
        };

        $outcome = (new SessionSwitch($this->tokens, $this->rotations, $this->context, $client, $target, $revoke, $this->transitions, $recheck))
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
     * wrote.
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
            fn () => $this->binding->authenticateAs($session->identity, $session->principal, $session->record, null, $session->tenant),
        );

        return SwitchResult::switched(new SignedInSession($session->identity, $session->principal, $session->record, $tokens, (string) $session->method));
    }
}
