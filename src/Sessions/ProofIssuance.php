<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Records a proof on an active session and issues it a new access token, in one
 * transaction on the session's connection: the shared step of a step-up and a
 * reauthentication.
 *
 * In order, with the session's row locked until the transaction ends, so a
 * revocation either commits first (and the proof is refused) or after (and the
 * new token dies at the next request, as every access token of a revoked
 * session does): the session must exist (`session_unknown`); be this guard's,
 * not revoked and not ended (`OwnedSession::refusal()`); belong to a person
 * (`machine_identity`); take the proof (the operation's own check, given the
 * session's start); and be admitted again as a refresh admits it (the owner,
 * the principal the session records and its tenant active, the method still
 * allowed, the principal still eligible). Then the proof is recorded and one
 * access token issued at `$now`, its `auth_time` and `amr` derived from the
 * proofs, the new one included, and answered with when it expires (the access
 * lifetime from `$now`, never past the session's end). Nothing else is written:
 * the refresh token, the deadlines and the session row stay as they were, so a
 * concurrent refresh's compare-and-swap is unaffected.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofIssuance
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     */
    public function __construct(

        /** The context of the guard whose sessions take proofs. */
        private GuardContext $context,

        /** The guard's token service, which issues the new access token. */
        private JwtTokenService $tokens,
    ) {}

    /**
     * Record the proof on the session the key names and issue it a new access
     * token, or refuse with as much as was resolved.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Proofs\NewProof  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonInterface): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $accepts
     * @return array{0: \SineMacula\Laravel\Authentication\Admission\Admitted, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 2: string, 3: \Carbon\CarbonImmutable}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    public function issue(mixed $sessionId, NewProof $proof, CarbonImmutable $now, \Closure $accepts): array|Refused
    {
        return SessionLookup::model()->getConnection()->transaction(fn (): array|Refused => $this->issueOn($sessionId, $proof, $now, $accepts));
    }

    /**
     * Lock, check, admit, record and issue, in the caller's transaction.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Proofs\NewProof  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonInterface): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $accepts
     * @return array{0: \SineMacula\Laravel\Authentication\Admission\Admitted, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 2: string, 3: \Carbon\CarbonImmutable}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function issueOn(mixed $sessionId, NewProof $proof, CarbonImmutable $now, \Closure $accepts): array|Refused
    {
        $session = SessionLookup::lock($sessionId);

        if ($session === null) {
            return new Refused(FailureReason::SESSION_UNKNOWN);
        }

        $refusal = $this->refusal($session, $now, $accepts);

        $admitted = $refusal === null ? $this->admit($session) : new Refused($refusal, session: $session);

        if ($admitted instanceof Refused) {
            return $admitted;
        }

        ProofWriter::record($session, $this->context->name(), $proof);

        $token   = $this->tokens->issueAccessToken($admitted->identity, $admitted->principal, $admitted->tenant, $session, $now);
        $expires = $this->tokens->lifetimes()->accessExpiry($now, WriteConnection::during($session, static fn (): ?CarbonImmutable => SessionDeadlines::liveEnd($session, $now)));

        return [$admitted, $session, $token, $expires];
    }

    /**
     * Why the locked session cannot take the proof now, or `null` when it can.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonInterface): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $accepts
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     */
    private function refusal(EloquentSession&Model $session, CarbonImmutable $now, \Closure $accepts): ?FailureReason
    {
        $live = OwnedSession::refusal($session, $this->context->name(), $now);

        if ($live !== null) {
            return $live;
        }

        $startedAt = WriteConnection::during($session, static fn (): ?CarbonInterface => $session->getSignedInAt());

        return SessionOwnership::isMachineOwned($session) ? FailureReason::MACHINE_IDENTITY : $accepts($session, $startedAt ?? $now);
    }

    /**
     * Admit the session again as a refresh admits it, as the principal it
     * records (`session_principal_mismatch` when that no longer resolves as
     * that very principal).
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function admit(EloquentSession&Model $session): Admitted|Refused
    {
        $hint     = $session->getAttribute(PrincipalReference::columns($session)[1]);
        $admitted = (new RefreshAdmission($this->context->name(), $this->context->provider(), $this->context->resolver()))->admit($session, $hint);

        if ($admitted instanceof Admitted && !PrincipalReference::isRecordedOn($session, $admitted->principal)) {
            return Refused::after(FailureReason::SESSION_PRINCIPAL_MISMATCH, $admitted);
        }

        if ($admitted instanceof Refused) {
            return new Refused($admitted->reason, $admitted->identity, $admitted->principal, $admitted->tenant, $session);
        }

        return $admitted;
    }
}
