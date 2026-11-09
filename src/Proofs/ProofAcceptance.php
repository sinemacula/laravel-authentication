<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Decides whether a proof an adapter hands over may be recorded: on a pending
 * session it satisfies, or on a session it steps up.
 *
 * Either takes only a further factor or a recovery code (an
 * `external_reauthentication` or a first-factor kind is refused: an external
 * reauthentication is recorded only through the package's own entry point, and
 * counts for MFA only through the acceptance of its evidence by the evidence
 * contract, `External\EvidenceAcceptance`), over any channel but `recovery`
 * (the application's own account recovery is a first factor that only
 * `SessionService::start()` records, never a further factor, so it can neither
 * add `mfa` nor satisfy a requirement that takes one), made for the operation's
 * purpose (`sign_in` for a pending session, or `enrollment` for the further
 * factor that confirms a factor enrolled while it waits; `step_up` for a
 * step-up), accepted by its adapter, and made no later than now and no earlier
 * than what it adds to (the time the pending session began waiting, or the
 * session's start): anything else is `proof_invalid`. Its binding must then
 * name the session's owner, the application and the session's key exactly:
 * anything else is `proof_binding_mismatch`.
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
     * Why the proof cannot satisfy the pending session of the guard, the
     * session having waited since the time given, or `null` when it can: a
     * further factor or recovery code made for the sign-in, or a further factor
     * confirming a factor enrolled while the session waited (its purpose
     * `enrollment`), accepted by its adapter, made by the session's owner on
     * the guard for the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @param  \Carbon\CarbonInterface  $since
     * @param  \Carbon\CarbonInterface  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public static function forPendingSession(ProofResult $proof, EloquentSession&Model $session, string $guard, CarbonInterface $since, CarbonInterface $now): ?FailureReason
    {
        $enrollment = $proof->kind === ProofKind::ADDITIONAL_FACTOR && $proof->binding->purpose === Purpose::ENROLLMENT;
        $purpose    = $enrollment ? Purpose::ENROLLMENT : Purpose::SIGN_IN;

        return self::invalid($proof, $purpose, $since, $now) ?? self::boundTo($proof, $session, $guard);
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
        return self::invalid($proof, Purpose::STEP_UP, $startedAt, $now) ?? self::boundTo($proof, $session, $guard);
    }

    /**
     * `proof_binding_mismatch` for a proof made by another identity than the
     * session's owner, on another application, or for another session; `null`
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    private static function boundTo(ProofResult $proof, EloquentSession&Model $session, string $guard): ?FailureReason
    {
        $bound = SessionOwnership::isOwner($session, $proof->binding->identity)
            && $proof->binding->application === $guard
            && IdentifierCoercion::matches($session->getSessionIdentifier(), $proof->binding->sessionId);

        return $bound ? null : FailureReason::PROOF_BINDING_MISMATCH;
    }

    /**
     * `proof_invalid` for a proof of a kind the operations do not take, over
     * the `recovery` channel, of another purpose, not accepted by its adapter,
     * or made after now or before what it adds to; `null` otherwise.
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

        $further = $proof->kind->isAdditional() && $proof->channel->kind !== ChannelKind::RECOVERY;
        $taken   = $further                     && $proof->binding->purpose === $purpose && $proof->evaluation->accepted;
        $timely  = $at <= $now->getTimestamp()  && $at >= $since->getTimestamp();

        return $taken && $timely ? null : FailureReason::PROOF_INVALID;
    }
}
