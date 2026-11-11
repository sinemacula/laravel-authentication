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
 * tenant, or both.
 *
 * Kept in a trait only to hold the service under the per-class method limit.
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
     * Switch the session the presented refresh token proves to the target;
     * `null` when nothing was presented.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return ($presented is null ? null : \SineMacula\Laravel\Authentication\Sessions\SwitchResult)
     *
     * @throws \Throwable
     */
    public function switchTo(
        #[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented,
        SwitchTarget $target,
        ClientContext $client,
        int|string|null $expectedSession = null,
    ): ?SwitchResult {
        $transport = $this->transport();

        if ($presented instanceof FailureReason) {
            return $this->refuseSwitch(SessionRefresh::handedIn($presented), $client);
        }

        if ($presented === null) {
            return null;
        }

        $refusal = $transport->judge($presented, $client);
        $result  = $refusal === null ? $this->switchWith($presented->token, $target, $transport, $client, $expectedSession) : $this->refuseSwitch($refusal, $client);

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
     * @param  int|string|null  $expectedSession
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switchWith(
        #[\SensitiveParameter] Secret $refreshToken,
        SwitchTarget $target,
        RefreshTokenTransport $transport,
        ClientContext $client,
        int|string|null $expectedSession,
    ): SwitchResult {
        $began   = CarbonImmutable::now()->startOfSecond();
        $recheck = $this->recheck($client, $began);
        $revoke  = function (EloquentSession&Model $record, CarbonImmutable $now) use ($client): bool {

            $event = new SessionRevoked(
                new EventContext($record->getGuard(), $client, session: $record, method: $record->getSignInMethod(), fromSession: true),
                RevocationReason::ROTATION_REUSE,
            );

            return $this->switchRevocations->revoke($record, RevocationReason::ROTATION_REUSE, $now, fn () => $this->context->dispatch($event));
        };

        $outcome = (new SessionSwitch(
            $this->tokens,
            $this->rotations,
            $this->context,
            $client,
            $target,
            $revoke,
            $this->transitions->forClient($client),
            $recheck,
            $expectedSession,
        ))
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
     * Report the switch once committed and rechecked, then bind the guard to
     * the switched session and answer it.
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
