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
 * Decides whether an adapter's proof may satisfy a pending session or step a
 * session up.
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
     * Why the proof cannot satisfy the pending session of the guard, waiting
     * since the time given, or `null` when it can.
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
     * Why the proof cannot step up the session of the guard, started at the
     * time given, or `null` when it can.
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
     * `proof_binding_mismatch` unless the proof is bound to the session's
     * owner, the guard and the session's key.
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
     * `proof_invalid` for a proof of the wrong kind, channel, purpose or time,
     * or one its adapter did not accept.
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
