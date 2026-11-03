<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\External\ExternalLink;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionGeneration;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;

/**
 * Reauthenticates a session of one guard with a result an external identity
 * provider verified, through the very link that established the session:
 * records an `external_reauthentication` proof on it and issues it a new access
 * token. It renews the session's authentication time and nothing else unless
 * the evidence contract accepts the provider's evidence: no refresh token is
 * issued, the session row, its deadlines and its provenance stay as they were,
 * and nothing is bound.
 *
 * In order: the application policy must allow `external_provider`
 * (`method_not_allowed`); the session the identifier names, read on the write
 * connection, must exist (`session_unknown`) and be one of this guard's live,
 * active sessions of a person (the reasons `ProofIssuance` gives); the result
 * must say when the provider authenticated the identity (`proof_invalid`); the
 * link contract must link it to an identity (`ExternalResultUnlinked`, then
 * `external_result_unlinked`), and that identity must own the session
 * (`link_mismatch`); then the result's evidence is judged for it. The proof is
 * then recorded and the token issued as `ProofIssuance` describes, the
 * session's row locked (after every lock the adapter took, the link contract's
 * included) and checked again: still of the same generation
 * (`session_unknown`), owned by the link's identity and established through
 * exactly the result's connection and the link's id, which its provenance
 * records (`link_mismatch`: a session established through another link of the
 * same identity, or through no link at all, never matches), and not begun after
 * the provider authenticated the identity (`proof_invalid`). Once the proof is
 * recorded, the session is judged against its tenant's authentication policy,
 * with that proof among its own, as every redemption is: a connection the
 * tenant no longer admits is `sso_required`, a further factor it now requires
 * and the session does not meet `additional_factor_required`, and either rolls
 * the proof back. Neither writes the session: the next refresh revokes it or
 * returns it to pending, and no version is recorded, since the row is never
 * written here.
 *
 * The proof is timed when the provider authenticated the identity (now, when
 * that is after now), so the access token's `auth_time`, the newest of the
 * session's proof times, becomes the later of its current value and the
 * provider's time, decided under the session's lock. Its `amr` and `mfa` change
 * only when the evidence was accepted. `Reauthenticated` reports it once
 * committed; a refusal reports `AuthenticationFailed` (flow `reauthentication`)
 * and is answered, never thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalReauthentication
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\ProofIssuance  $issuance
     * @param  \SineMacula\Laravel\Authentication\Sessions\ExternalResults  $results
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation  $evaluation
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     */
    public function __construct(

        /** The context of the guard whose sessions are reauthenticated. */
        private GuardContext $context,

        /** Records the proof and issues the new access token. */
        private ProofIssuance $issuance,

        /** Finds the result's link and judges its evidence. */
        private ExternalResults $results,

        /** Asks the application policy whether it allows external sign-in. */
        private PendingEvaluation $evaluation,

        /** Defers `Reauthenticated` until the proof commits. */
        private AfterCommit $afterCommit,
    ) {}

    /**
     * Reauthenticate the session the identifier names with the result.
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    public function reauthenticate(mixed $sessionId, ExternalResult $result): AccessTokenResult
    {
        $now     = CarbonImmutable::now()->startOfSecond();
        $checked = $this->checked($sessionId, $result, $now);

        if ($checked instanceof Refused) {
            return $this->fail($checked);
        }

        [$stored, $link, $at]    = $checked;
        [$evaluation, $evidence] = $this->results->acceptance($result, $link->identity, $now);

        $channel = new Channel(ChannelKind::EXTERNAL_PROVIDER, $result->connectionId);
        $proof   = new NewProof(
            ProofKind::EXTERNAL_REAUTHENTICATION,
            Purpose::REAUTHENTICATE,
            SignInMethodManager::EXTERNAL_METHOD,
            $channel,
            null,
            new ObservedProperties,
            $evaluation,
            [FirstFactor::EXTERNAL_PROVIDER_METHOD],
            $at,
            $evidence,
        );

        $guard  = $this->context->name();
        $issued = $this->issuance->issue(
            $stored->getSessionIdentifier(),
            $proof,
            static fn (EloquentSession&Model $locked, CarbonInterface $startedAt): ?FailureReason => self::refusal($locked, $stored, $link, $result->connectionId, $at, $startedAt),
            static fn (Admitted $admitted, EloquentSession&Model $locked, CarbonImmutable $now): ?FailureReason => self::shortfall($guard, $admitted, $locked, $now),
        );

        if ($issued instanceof Refused) {
            return $this->fail($issued->reason === FailureReason::SESSION_UNKNOWN ? new Refused(FailureReason::SESSION_UNKNOWN, session: $stored) : $issued);
        }

        [$admitted, $record, $token, $expires] = $issued;

        $event = new Reauthenticated(new EventContext(
            $this->context->name(),
            $this->context->client(),
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            $record,
            SignInMethodManager::EXTERNAL_METHOD,
        ));

        $this->afterCommit->run($record, fn () => $this->context->dispatch($event));

        return AccessTokenResult::issued($token, $record, $expires);
    }

    /**
     * Why the session the identifier names has no standing for the identity
     * through the connection and the link, or `null` when it has: of this
     * guard, live, active and a person's, owned by the identity and established
     * through exactly that connection and that link, or any link when none is
     * given. Inside a transaction on the session model's connection its row is
     * locked until the transaction ends; outside one it is read on the write
     * connection and nothing is locked.
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  ?string  $linkId
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function standing(mixed $sessionId, Identity $identity, string $connectionId, ?string $linkId = null): ?FailureReason
    {
        if (!$this->evaluation->allowsMethod(SignInMethodManager::EXTERNAL_METHOD)) {
            return FailureReason::METHOD_NOT_ALLOWED;
        }

        $stored = SessionLookup::model()->getConnection()->transactionLevel() > 0 ? SessionLookup::lock($sessionId) : SessionLookup::find($sessionId);

        if ($stored === null) {
            return FailureReason::SESSION_UNKNOWN;
        }

        return OwnedSession::refusal($stored, $this->context->name(), CarbonImmutable::now()->startOfSecond())
            ?? (SessionOwnership::isMachineOwned($stored) ? FailureReason::MACHINE_IDENTITY : null)
            ?? (self::isEstablishedThrough($stored, $identity, $connectionId, $linkId) ? null : FailureReason::LINK_MISMATCH);
    }

    /**
     * Check the session, the provider's time and the link before anything is
     * locked: the stored session, the link and the time the proof is recorded
     * at, or the refusal.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \SineMacula\Laravel\Authentication\External\ExternalLink, 2: \Carbon\CarbonImmutable}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function checked(mixed $sessionId, ExternalResult $result, CarbonImmutable $now): array|Refused
    {
        $stored = $this->stored($sessionId, $result, $now);

        if ($stored instanceof Refused) {
            return $stored;
        }

        [$record, $at] = $stored;

        $link = $this->results->link($result, $this->context->client());

        if ($link === null || !SessionOwnership::isOwner($record, $link->identity)) {
            return new Refused($link === null ? FailureReason::EXTERNAL_RESULT_UNLINKED : FailureReason::LINK_MISMATCH, session: $record);
        }

        return [$record, $link, $at->greaterThan($now) ? $now : $at];
    }

    /**
     * Check the method, the session the identifier names as stored and the
     * provider's time: the stored session and the provider's time, or the
     * refusal.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \Carbon\CarbonImmutable}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function stored(mixed $sessionId, ExternalResult $result, CarbonImmutable $now): array|Refused
    {
        if (!$this->evaluation->allowsMethod(SignInMethodManager::EXTERNAL_METHOD)) {
            return new Refused(FailureReason::METHOD_NOT_ALLOWED);
        }

        $stored = SessionLookup::find($sessionId);

        if ($stored === null) {
            return new Refused(FailureReason::SESSION_UNKNOWN);
        }

        $at      = $result->authenticatedAt;
        $refusal = OwnedSession::refusal($stored, $this->context->name(), $now)
            ?? (SessionOwnership::isMachineOwned($stored) ? FailureReason::MACHINE_IDENTITY : null);

        return $refusal === null && $at !== null ? [$stored, $at] : new Refused($refusal ?? FailureReason::PROOF_INVALID, session: $stored);
    }

    /**
     * Why the locked row cannot take the proof, beyond what `ProofIssuance`
     * checks, or `null` when it can.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $stored
     * @param  \SineMacula\Laravel\Authentication\External\ExternalLink  $link
     * @param  string  $connectionId
     * @param  \Carbon\CarbonImmutable  $at
     * @param  \Carbon\CarbonInterface  $startedAt
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     */
    private static function refusal(
        EloquentSession&Model $locked,
        EloquentSession&Model $stored,
        ExternalLink $link,
        string $connectionId,
        CarbonImmutable $at,
        CarbonInterface $startedAt,
    ): ?FailureReason {
        return match (true) {
            !SessionGeneration::isSame($locked, $stored)                                    => FailureReason::SESSION_UNKNOWN,
            !self::isEstablishedThrough($locked, $link->identity, $connectionId, $link->id) => FailureReason::LINK_MISMATCH,
            $at->getTimestamp() < $startedAt->getTimestamp()                                => FailureReason::PROOF_INVALID,
            default                                                                         => null,
        };
    }

    /**
     * Why the session, with the proof just recorded, no longer meets its
     * tenant's authentication policy, as a refresh judges it but writing
     * nothing: `sso_required` for a session the next refresh would revoke,
     * `additional_factor_required` for one it would return to pending; `null`
     * when it meets it.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private static function shortfall(string $guard, Admitted $admitted, EloquentSession&Model $session, CarbonImmutable $now): ?FailureReason
    {
        return match (TenantPolicyCheck::check($guard, $admitted->identity, $admitted->principal, $admitted->tenant, $session, $now)->standing) {
            TenantPolicyStanding::SSO_REQUIRED    => FailureReason::SSO_REQUIRED,
            TenantPolicyStanding::FACTOR_REQUIRED => FailureReason::ADDITIONAL_FACTOR_REQUIRED,
            TenantPolicyStanding::MET             => null,
        };
    }

    /**
     * Whether the session is the identity's and its provenance records exactly
     * the connection and the link, or any link when none is given, each
     * compared byte for byte; a session with no provenance, or one that records
     * no link, never is.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  ?string  $linkId
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function isEstablishedThrough(EloquentSession&Model $session, Identity $identity, string $connectionId, ?string $linkId): bool
    {
        if (!SessionOwnership::isOwner($session, $identity)) {
            return false;
        }

        $provenance = SessionProofs::provenance($session);

        return $provenance !== null && $provenance->connectionId === $connectionId && $provenance->linkId !== null && ($linkId === null || $provenance->linkId === $linkId);
    }

    /**
     * Report a refused reauthentication with `AuthenticationFailed` and answer
     * it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     */
    private function fail(Refused $refused): AccessTokenResult
    {
        $session = $refused->session;
        $context = new EventContext(
            $this->context->name(),
            $this->context->client(),
            $refused->identity,
            $refused->principal,
            $refused->tenant,
            $session,
            SignInMethodManager::EXTERNAL_METHOD,
            fromSession: $session !== null,
        );

        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::REAUTHENTICATION, $refused->reason));

        return AccessTokenResult::failed($refused->reason);
    }
}
