<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SessionReauthentication;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;

/**
 * The session service's step-up and reauthentication methods, which
 * `SessionStepUp` and `SessionReauthentication` carry out.
 *
 * They are delegations with no state of their own; they sit in a trait only so
 * the service stays within the number of methods one class may declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ProvesSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionStepUp Steps sessions up with the further factors adapters verified, on the guard's context. */
    private readonly SessionStepUp $stepUps;

    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionReauthentication Reauthenticates sessions with their first factor, on the guard's context. */
    private readonly SessionReauthentication $reauthentications;

    /**
     * Step the session the proof is bound to up with the further factor (or
     * recovery code) its adapter verified, and issue the session a new access
     * token only: the session, its refresh token and its deadlines are kept.
     *
     * The proof must be an `additional_factor` or `recovery_code`, made for
     * `step_up`, accepted, made no later than now and no earlier than the
     * session started (`proof_invalid`), and bound to the session's owner, this
     * guard and the session's key (`proof_binding_mismatch`); the session,
     * locked while the proof is recorded, must be one of this guard's live
     * sessions (`session_unknown`, `session_guard_mismatch`, `session_revoked`,
     * `session_expired`, `machine_identity`) and admitted again as a refresh
     * is. The new token's `auth_time` is the newest of the session's proof
     * times, so never earlier than the proof's, and its `amr` gains the proof's
     * values, and `mfa` when the evaluation reports multifactor authentication.
     * Once committed, `SteppedUp` reports it; a refusal reports
     * `AuthenticationFailed` (flow `step_up`) and is answered, never thrown.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    public function stepUp(ProofResult $proof): AccessTokenResult
    {
        return $this->stepUps->stepUp($proof);
    }

    /**
     * Reauthenticate the session with its identity's first factor, through the
     * named sign-in method and the input the client sent, and issue the session
     * a new access token only, whose `auth_time` is renewed and whose `amr` is
     * unchanged.
     *
     * The method must be allowed (`method_not_allowed`) and may not be a
     * machine credential kind (an `InvalidArgumentException`); the session must
     * be one of this guard's live sessions, as for a step-up; the attempt is
     * counted under the guard's `sign_in` limits (`rate_limited`) and verified
     * in the credential timebox; the verified identity must be the session's
     * owner (`invalid_credentials` otherwise, as for a wrong secret). Once
     * committed, `Reauthenticated` reports it; a refusal reports
     * `AuthenticationFailed` (flow `reauthentication`) and is answered, never
     * thrown, a concealed reason as `invalid_credentials`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function reauthenticate(Session $session, string $method, #[\SensitiveParameter] array $input): AccessTokenResult
    {
        return $this->reauthentications->reauthenticate($session, $method, $input);
    }
}
