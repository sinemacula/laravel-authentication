<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Context\ContextForgetting;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Records a proof on an active session and issues it a new access token in one
 * transaction: the shared step of a step-up and a reauthentication.
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
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     */
    public function __construct(

        /** The context of the guard whose sessions take proofs. */
        private GuardContext $context,

        /** The guard's token service, which issues the new access token. */
        private JwtTokenService $tokens,

        /** Defers forgetting the authentication contexts of the session until its proof commits or rolls back. */
        private AfterCommit $afterCommit,
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
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonInterface): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $accepts
     * @param  ?\Closure(\SineMacula\Laravel\Authentication\Admission\Admitted, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonImmutable): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $admits
     * @return array{0: \SineMacula\Laravel\Authentication\Admission\Admitted, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 2: \SineMacula\Laravel\Authentication\Secrets\Secret, 3: \Carbon\CarbonImmutable}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    public function issue(mixed $sessionId, NewProof $proof, \Closure $accepts, ?\Closure $admits = null): array|Refused
    {
        try {
            return SessionLookup::model()->getConnection()->transaction(fn (): array|Refused => $this->issueOn($sessionId, $proof, $accepts, $admits));
        } catch (IssuanceRefused $refusal) {
            return $refusal->refused;
        }
    }

    /**
     * Lock, check, admit, record, judge again and issue, in the caller's
     * transaction.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Proofs\NewProof  $proof
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonInterface): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $accepts
     * @param  ?\Closure(\SineMacula\Laravel\Authentication\Admission\Admitted, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonImmutable): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $admits
     * @return array{0: \SineMacula\Laravel\Authentication\Admission\Admitted, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 2: \SineMacula\Laravel\Authentication\Secrets\Secret, 3: \Carbon\CarbonImmutable}|\SineMacula\Laravel\Authentication\Admission\Refused
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
     * @throws \SineMacula\Laravel\Authentication\Sessions\IssuanceRefused
     */
    private function issueOn(mixed $sessionId, NewProof $proof, \Closure $accepts, ?\Closure $admits): array|Refused
    {
        $session = SessionLookup::lock($sessionId);

        if ($session === null) {
            return new Refused(FailureReason::SESSION_UNKNOWN);
        }

        $now     = CarbonImmutable::now()->startOfSecond();
        $refusal = $this->refusal($session, $now, $accepts);

        $admitted = $refusal === null ? $this->admit($session) : new Refused($refusal, session: $session);

        if ($admitted instanceof Refused) {
            return $admitted;
        }

        IssuanceGuard::hold($session);

        // Registered before the proof is written, so a context `$admits` builds
        // is forgotten when it refuses or throws.
        ContextForgetting::onSettle($this->afterCommit, $session);

        ProofWriter::record($session, $this->context->name(), $proof);

        self::assertAdmits($admits, $admitted, $session, $now);

        $token = $this->tokens->issueGuardedAccessToken($admitted->identity, $admitted->principal, $admitted->tenant, $session, $now);

        return [$admitted, $session, $token->token, $token->expiresAt];
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
     * Judge the admitted session once more now its proof is recorded; a reason
     * refuses the issuance and rolls the proof back.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  ?\Closure(\SineMacula\Laravel\Authentication\Admission\Admitted, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonImmutable): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $admits
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Sessions\IssuanceRefused
     */
    private static function assertAdmits(?\Closure $admits, Admitted $admitted, EloquentSession&Model $session, CarbonImmutable $now): void
    {
        $shortfall = $admits === null ? null : $admits($admitted, $session, $now);

        if ($shortfall !== null) {
            throw new IssuanceRefused(new Refused($shortfall, $admitted->identity, $admitted->principal, $admitted->tenant, $session));
        }
    }

    /**
     * Admit the session again as a refresh admits it, as the principal it
     * records.
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
