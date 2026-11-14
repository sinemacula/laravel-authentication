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
use SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\External\ExternalLink;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionGeneration;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;

/**
 * Reauthenticates a session with a result an external identity provider
 * verified, through the very link that established the session.
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
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    public function reauthenticate(mixed $sessionId, ExternalResult $result, ClientContext $client): AccessTokenResult
    {
        $now     = CarbonImmutable::now()->startOfSecond();
        $checked = $this->checked($sessionId, $result, $now, $client);

        if ($checked instanceof Refused) {
            return $this->fail($checked, $result, $client);
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
            static fn (Admitted $admitted, EloquentSession&Model $locked, CarbonImmutable $now): ?FailureReason => self::shortfall($guard, $admitted, $locked, $client, $now),
        );

        if ($issued instanceof Refused) {
            return $this->fail($issued->reason === FailureReason::SESSION_UNKNOWN ? new Refused(FailureReason::SESSION_UNKNOWN, session: $stored) : $issued, $result, $client);
        }

        [$admitted, $record, $token, $expires] = $issued;

        $method   = SignInMethodManager::EXTERNAL_METHOD;
        $event    = new Reauthenticated(new EventContext($this->context->name(), $client, $admitted->identity, $admitted->principal, $admitted->tenant, $record, $method));
        $redeemed = new ExternalResultRedeemed(new EventContext(
            $this->context->name(),
            $client,
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            $record,
            $method,
            connectionId: $result->connectionId,
            requestReference: $result->requestReference,
        ), AuthenticationFlow::REAUTHENTICATION);

        $this->afterCommit->run($record, function () use ($event, $redeemed): void {
            $this->context->dispatch($event);
            $this->context->dispatch($redeemed);
        });

        return AccessTokenResult::issued($token, $record, $expires);
    }

    /**
     * Why the session the identifier names has no standing for the identity
     * through the connection and the link; `null` when it has.
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

        $locks  = SessionLookup::model()->getConnection()->transactionLevel() > 0;
        $stored = $locks ? SessionLookup::lock($sessionId) : SessionLookup::find($sessionId);

        if ($stored === null) {
            return FailureReason::SESSION_UNKNOWN;
        }

        return OwnedSession::refusal($stored, $this->context->name(), CarbonImmutable::now()->startOfSecond())
            ?? (SessionOwnership::isMachineOwned($stored) ? FailureReason::MACHINE_IDENTITY : null)
            ?? (self::isEstablishedThrough($stored, $identity, $connectionId, $linkId, $locks) ? null : FailureReason::LINK_MISMATCH);
    }

    /**
     * The stored session, the link and the proof's time, or the refusal, before
     * anything is locked.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
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
    private function checked(mixed $sessionId, ExternalResult $result, CarbonImmutable $now, ClientContext $client): array|Refused
    {
        $stored = $this->stored($sessionId, $result, $now);

        if ($stored instanceof Refused) {
            return $stored;
        }

        [$record, $at] = $stored;

        $link = $this->results->link($result, $client);

        if ($link === null || !SessionOwnership::isOwner($record, $link->identity) || !ExternalResults::isNamedLink($result, $link)) {
            return new Refused($link === null ? FailureReason::EXTERNAL_RESULT_UNLINKED : FailureReason::LINK_MISMATCH, session: $record);
        }

        return [$record, $link, $at->greaterThan($now) ? $now : $at];
    }

    /**
     * The stored session and the provider's time, or the refusal.
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
     * Why the locked session, with the proof just recorded, no longer meets its
     * tenant's authentication policy; `null` when it meets it.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private static function shortfall(string $guard, Admitted $admitted, EloquentSession&Model $session, ClientContext $client, CarbonImmutable $now): ?FailureReason
    {
        return match (TenantPolicyCheck::check($guard, $admitted, $session, $client, $now, new ProofSource(current: true))->standing) {
            TenantPolicyStanding::SSO_REQUIRED    => FailureReason::SSO_REQUIRED,
            TenantPolicyStanding::FACTOR_REQUIRED => FailureReason::ADDITIONAL_FACTOR_REQUIRED,
            TenantPolicyStanding::MET             => null,
        };
    }

    /**
     * Whether the session is the identity's and its provenance records exactly
     * the connection and the link, or any link when none is given.
     *
     * Provenance is fixed per generation; an unchecked row reads it current.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  ?string  $linkId
     * @param  bool  $current
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function isEstablishedThrough(EloquentSession&Model $session, Identity $identity, string $connectionId, ?string $linkId, bool $current = false): bool
    {
        if (!SessionOwnership::isOwner($session, $identity)) {
            return false;
        }

        $provenance = SessionProofs::provenance($session, $current);

        return $provenance !== null && $provenance->connectionId === $connectionId && $provenance->linkId !== null && ($linkId === null || $provenance->linkId === $linkId);
    }

    /**
     * Report a refused reauthentication and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     */
    private function fail(Refused $refused, ExternalResult $result, ClientContext $client): AccessTokenResult
    {
        $session = $refused->session;
        $context = new EventContext(
            $this->context->name(),
            $client,
            $refused->identity,
            $refused->principal,
            $refused->tenant,
            $session,
            SignInMethodManager::EXTERNAL_METHOD,
            fromSession: $session !== null,
            connectionId: $result->connectionId,
            requestReference: $result->requestReference,
        );

        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::REAUTHENTICATION, $refused->reason));

        return AccessTokenResult::failed($refused->reason);
    }
}
