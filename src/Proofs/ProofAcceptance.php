<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Decides whether a proof an adapter hands over may be recorded: on a pending
 * sign-in it completes, or on a session it steps up.
 *
 * Either takes only a further factor or a recovery code (an
 * `external_reauthentication` or a first-factor kind is refused, which is how
 * an external reauthentication never counts for MFA until something accepts its
 * evidence, which nothing does yet), made for the operation's purpose
 * (`sign_in` for a completion, `step_up` for a step-up), accepted by its
 * adapter, and made no later than now and no earlier than what it adds to (the
 * pending sign-in's first factor, or the session's start): anything else is
 * `proof_invalid`. Its binding must then name the identity, the application and
 * the pending sign-in's id or the session's key exactly: anything else is
 * `proof_binding_mismatch`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ProofAcceptance
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the proof cannot complete the pending sign-in, whose first factor was
     * verified at the time given, or `null` when it can.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @param  \Carbon\CarbonInterface  $verifiedAt
     * @param  \Carbon\CarbonInterface  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public static function forPendingSignIn(ProofResult $proof, PendingSignIn $pending, CarbonInterface $verifiedAt, CarbonInterface $now): ?FailureReason
    {
        $identity = $proof->binding->identity;

        $madeBy = $identity instanceof Model
            && $identity->getMorphClass() === $pending->authenticatable_type
            && IdentifierCoercion::matches($identity->getKey(), $pending->authenticatable_id);

        $bound = $madeBy
            && $proof->binding->application === $pending->guard
            && IdentifierCoercion::matches($pending->id, $proof->binding->sessionId);

        return self::invalid($proof, Purpose::SIGN_IN, $verifiedAt, $now) ?? ($bound ? null : FailureReason::PROOF_BINDING_MISMATCH);
    }

    /**
     * Why the proof cannot step the session of the guard up, the session having
     * started at the time given, or `null` when it can.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @param  \Carbon\CarbonInterface  $startedAt
     * @param  \Carbon\CarbonInterface  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public static function forSession(ProofResult $proof, EloquentSession&Model $session, string $guard, CarbonInterface $startedAt, CarbonInterface $now): ?FailureReason
    {
        $bound = SessionOwnership::isOwner($session, $proof->binding->identity)
            && $proof->binding->application === $guard
            && IdentifierCoercion::matches($session->getSessionIdentifier(), $proof->binding->sessionId);

        return self::invalid($proof, Purpose::STEP_UP, $startedAt, $now) ?? ($bound ? null : FailureReason::PROOF_BINDING_MISMATCH);
    }

    /**
     * `proof_invalid` for a proof of a kind the operations do not take, of
     * another purpose, not accepted by its adapter, or made after now or before
     * what it adds to; `null` otherwise.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  \Carbon\CarbonInterface  $since
     * @param  \Carbon\CarbonInterface  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    private static function invalid(ProofResult $proof, Purpose $purpose, CarbonInterface $since, CarbonInterface $now): ?FailureReason
    {
        $at = $proof->authenticatedAt->getTimestamp();

        $taken  = $proof->kind->isAdditional() && $proof->binding->purpose === $purpose && $proof->evaluation->accepted;
        $timely = $at <= $now->getTimestamp()  && $at >= $since->getTimestamp();

        return $taken && $timely ? null : FailureReason::PROOF_INVALID;
    }
}
