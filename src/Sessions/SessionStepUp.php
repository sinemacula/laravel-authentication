<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SteppedUp;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ProofAcceptance;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;

/**
 * Steps a session of one guard up with a further factor an adapter verified:
 * records the proof on the session and issues it a new access token, whose
 * `auth_time` is the newest of the session's proof times (so never earlier than
 * the proof's) and whose `amr` gains its values (and `mfa` when its evaluation
 * reports multifactor authentication). It never issues a refresh token, keeps
 * the session, its key, its refresh token and its deadlines, and binds nothing:
 * the request it answers is already authenticated.
 *
 * The session is the one the proof's binding names, locked and checked as
 * `ProofIssuance` describes, and the proof must be one `ProofAcceptance`
 * accepts for a step-up. Once committed, `SteppedUp` reports it; a refusal
 * reports `AuthenticationFailed` (flow `step_up`) and is answered, never
 * thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionStepUp
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\ProofIssuance  $issuance
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     */
    public function __construct(

        /** The context of the guard whose sessions are stepped up. */
        private GuardContext $context,

        /** Records the proof and issues the new access token. */
        private ProofIssuance $issuance,

        /** Defers `SteppedUp` until the proof commits. */
        private AfterCommit $afterCommit,
    ) {}

    /**
     * Step the session the proof is bound to up with it.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    public function stepUp(ProofResult $proof, ClientContext $client): AccessTokenResult
    {
        $now   = CarbonImmutable::now()->startOfSecond();
        $guard = $this->context->name();

        $accepts = static fn (EloquentSession&Model $session, CarbonInterface $since): ?FailureReason => ProofAcceptance::forSession($proof, $session, $guard, $since, $now);

        $outcome = $this->issuance->issue($proof->binding->sessionId, NewProof::fromResult($proof), $accepts);

        if ($outcome instanceof Refused) {

            $session = $outcome->session;
            $context = new EventContext($guard, $client, $outcome->identity, $outcome->principal, $outcome->tenant, $session, $proof->method, fromSession: $session !== null);

            $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::STEP_UP, $outcome->reason));

            return AccessTokenResult::failed($outcome->reason);
        }

        [$admitted, $session, $token, $expires] = $outcome;

        $event = new SteppedUp(new EventContext($guard, $client, $admitted->identity, $admitted->principal, $admitted->tenant, $session, $proof->method), $proof->kind);

        $this->afterCommit->run($session, fn () => $this->context->dispatch($event));

        return AccessTokenResult::issued($token, $session, $expires);
    }
}
