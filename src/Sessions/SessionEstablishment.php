<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;

/**
 * Takes a sign-in whose identity is admitted on to its session, in the order
 * sign-in takes (see `PendingEvaluation`): the principal selected, the
 * identity-level factor policy, and, with a principal, the tenant it is to be
 * active in and that tenant's authentication policy, judged against the
 * sign-in's own evidence (a connection it requires and the sign-in did not use
 * refuses it as `sso_required`; a further factor it requires is owed as the
 * identity's own is). With nothing outstanding the session is written active
 * with its first pair; otherwise it is written pending, waiting on the further
 * factor, then the choice of principal, with its pending credential and no
 * token. Either way it records the sign-in's first-factor proof and provenance.
 *
 * Every sign-in is a new session. A session the client proved it holds (with
 * the refresh token of its previous session) is revoked (`superseded`) by an
 * active sign-in that replaces it, in the same transaction, or by a pending
 * one's first activation; nothing else is ever revoked, however alike the
 * client is, and the replaced session's proofs stay with it.
 *
 * It schedules what reports the session once committed on the session's
 * connection (`SessionPending`, or `SessionRevoked` for the session replaced,
 * `SessionCreated` and `SignedIn`, then, for a session an external provider's
 * result established, `ExternalResultRedeemed` with the connection and the
 * request reference) and never binds the guard: the session service binds after
 * it returns, so a bind listener that throws cannot withhold a report. It runs
 * on the guard's context: its events carry the client of the sign-in they
 * report, and go to the context's dispatcher as it is when they are dispatched.
 * What reports the session waits, beyond its commit, for the call's check of
 * the session's identity, principal and tenant (`AdmissionRecheck`), and never
 * runs when the check ends the session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionEstablishment
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Sessions\ProvenSessions  $proof
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation  $evaluation
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions are established. */
        private GuardContext $context,

        /** Writes the session, active or pending, revoking the one an active one replaces. */
        private SessionWriter $writer,

        /** Decides which session a client proved it holds. */
        private ProvenSessions $proof,

        /** The checks a sign-in passes in order. */
        private PendingEvaluation $evaluation,

        /** Defers the lifecycle events until the writes commit. */
        private AfterCommit $afterCommit,

        /** Container the application policy and the configuration are resolved from. */
        private Container $container,
    ) {}

    /**
     * Select the principal the admitted identity's sign-in acts as, or find the
     * principals it is to choose from: a sign-in whose deadline
     * (`SignInContext::$notAfter`) has already passed fails as
     * `session_expired`, before anything is read; then the principal named, or
     * the only one the application admits, or none and the principals to choose
     * from (see `PendingEvaluation::selection()`).
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $named
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return array{0: ?\SineMacula\Laravel\Authentication\Contracts\Principal, 1: list<\SineMacula\Laravel\Authentication\Contracts\Principal>}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function select(Identity $identity, ?Principal $named, SignInContext $context): array|Refused
    {
        if ($context->hasPassedDeadline(CarbonImmutable::now()->startOfSecond())) {
            return new Refused(FailureReason::SESSION_EXPIRED, $identity);
        }

        $selection = $this->evaluation->selection($identity, $named);

        return $selection instanceof FailureReason ? new Refused($selection, $identity) : $selection;
    }

    /**
     * Take the sign-in on from its selection to its session: a deadline that
     * passed since the selection fails as `session_expired`, before anything is
     * written; then check the client's proof of an existing session (for the
     * principal selected, or any of the identity's when none is), ask the
     * identity-level factor policy, and with a principal admit the tenant it is
     * to be active in; then write the session active when nothing is
     * outstanding, replacing the proven session, or pending otherwise. When the
     * proven session changed before an active sign-in could replace it, the
     * sign-in is judged again without it, factor policy included; it never
     * retries the session.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array{0: ?\SineMacula\Laravel\Authentication\Contracts\Principal, 1: list<\SineMacula\Laravel\Authentication\Contracts\Principal>}  $selection
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @param  ?list<array<string, string>>  $attemptWindows
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    public function proceed(
        Identity $identity,
        array $selection,
        ?string $identifierType,
        SignInContext $context,
        SignInProof $proof,
        AdmissionRecheck $recheck,
        ?array $attemptWindows = null,
    ): Refused|SignInResult {
        [$principal] = $selection;

        $now = CarbonImmutable::now()->startOfSecond();

        if ($context->hasPassedDeadline($now)) {
            return new Refused(FailureReason::SESSION_EXPIRED, $identity, $principal);
        }

        $proven = $context->refreshToken === null
            ? null
            : $this->proof->provenSessionOf($this->context->name(), $identity, $principal, $context->refreshToken);

        return $this->establish($identity, $selection, $identifierType, $context, $proof, $attemptWindows, $proven, $now, $recheck);
    }

    /**
     * Establish the sign-in's session on the proven session (or none).
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array{0: ?\SineMacula\Laravel\Authentication\Contracts\Principal, 1: list<\SineMacula\Laravel\Authentication\Contracts\Principal>}  $selection
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @param  ?list<array<string, string>>  $attemptWindows
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $proven
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function establish(
        Identity $identity,
        array $selection,
        ?string $identifierType,
        SignInContext $context,
        SignInProof $proof,
        ?array $attemptWindows,
        (EloquentSession&Model)|null $proven,
        CarbonImmutable $now,
        AdmissionRecheck $recheck,
    ): Refused|SignInResult {
        [$principal, $principals] = $selection;

        $evidence = SessionEvidence::of($proof);
        $owed     = $this->evaluation->owedFactor($identity, $evidence->firstFactor, $context->client, $context->clientName, $context->platform, $proven, null, $now, $evidence);
        $tenant   = $principal === null ? null : $this->evaluation->destination($principal, $context->tenant);

        if ($tenant instanceof FailureReason) {
            return new Refused($tenant, $identity, $principal, session: $proven);
        }

        $policy = $this->evaluation->tenantPolicy($identity, $principal, $tenant, null, $now, $evidence);

        if ($policy->standing === TenantPolicyStanding::SSO_REQUIRED) {
            return new Refused(FailureReason::SSO_REQUIRED, $identity, $principal, $tenant, $proven);
        }

        $outstanding = Requirement::strictest($owed, $policy->factor);
        $requires    = PendingEvaluation::requirements($outstanding, $principal);
        $writer      = $this->writer->underTenantPolicy($policy->version);

        if ($principal === null || $requires !== []) {
            $draft = new PendingSessionDraft($identity, $principal, $tenant, $requires, $identifierType, $proof, $proven, $attemptWindows);

            return $this->wait($writer, $draft, $outstanding, $requires[0] === PendingRequirement::PRINCIPAL ? $principals : [], $context, $now, $recheck);
        }

        $session = $this->write($writer, new Admitted($identity, $principal, $tenant, $proven), $identifierType, $context, $proof, $now);

        return $session === null
            ? $this->establish($identity, $selection, $identifierType, $context, $proof, $attemptWindows, null, $now, $recheck)
            : $this->signedIn($session, $proven, $tenant, $context, $proof, $recheck);
    }

    /**
     * Write the sign-in's session pending, waiting on what is outstanding, and
     * schedule `SessionPending` for once it is committed and its identity, and
     * the principal and tenant it records if any, are checked again
     * (`AdmissionRecheck`). The requirement is what its authentication still
     * falls short of; the principals are the ones the pending session lists,
     * given only when the choice is the first requirement, so none is shown
     * while a factor is outstanding.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSessionDraft  $draft
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $outstanding
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function wait(
        SessionWriter $writer,
        PendingSessionDraft $draft,
        Requirement $outstanding,
        array $principals,
        SignInContext $context,
        CarbonImmutable $now,
        AdmissionRecheck $recheck,
    ): SignInResult {
        $ttl = PendingState::ttlSeconds($this->container->make(Repository::class));

        [$record, $credential] = $writer->createPending($draft, $context, $this->lifetimes(), $now, $ttl);

        [$identity, $principal, $tenant, $requires, $method] = [$draft->identity, $draft->principal, $draft->tenant, $draft->requires, $draft->proof->method];

        $expiresAt = PendingState::expiry($now, $ttl, $record->getAbsoluteExpiresAt());
        $pending   = new PendingSession(
            $record->getSessionIdentifier(),
            $this->context->name(),
            $identity,
            $principal,
            $tenant,
            $requires,
            $method,
            $expiresAt,
            $record,
            $outstanding,
            $draft->proof->recorded(),
            $principals,
        );
        $event = new SessionPending(
            new EventContext($this->context->name(), $context->client, $identity, $principal, $tenant, $record, $method),
            array_map(static fn (PendingRequirement $requirement): string => $requirement->value, $requires),
            $expiresAt,
        );
        $redeemed = $this->redeemed($draft->proof, $context->client, $identity, $principal, $tenant, $record);

        $recheck->signIn($record, $identity, $principal, $tenant);

        $recheck->then($record, function () use ($event, $redeemed): void {

            $this->context->dispatch($event);

            if ($redeemed === null) {
                return;
            }

            $this->context->dispatch($redeemed);
        });

        return SignInResult::pending($pending, $credential);
    }

    /**
     * Write the active session of an admitted sign-in, with the guard's
     * lifetimes, by the writer for the tenant policy version it answered at: a
     * new session, replacing the proven one (the admission's) when there is
     * one. The session records the method (the proof's) and the type of
     * identifier the sign-in used, which a later switch admits its target with,
     * and the sign-in's proofs and provenance. `null` when the proven session
     * changed before it could be replaced.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function write(SessionWriter $writer, Admitted $admitted, ?string $identifierType, SignInContext $context, SignInProof $proof, CarbonImmutable $now): ?SignedInSession
    {
        return $admitted->session === null
            ? $writer->create($admitted, $identifierType, $context, $this->lifetimes(), $now, $context->client, $proof)
            : $writer->replace($admitted, $identifierType, $context, $this->lifetimes(), $now, $context->client, $proof);
    }

    /**
     * The guard's lifetimes, as the application policy gives them.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lifetimes(): TokenLifetimes
    {
        return $this->container->make(ApplicationPolicy::class)->lifetimes($this->context->name());
    }

    /**
     * Schedule the reports of a written active session, and answer it, once the
     * session is committed on the session's own connection: `SessionRevoked`
     * (`superseded`) for the session it replaced, if any, then, once its
     * identity, principal and tenant are checked again (`AdmissionRecheck`),
     * `SessionCreated` and `SignedIn`, in turn, so a listener that throws stops
     * the reports after its own.
     *
     * The replaced session's revocation is reported with its guard (the
     * sign-in's own) and the method it records, the sign-in's client, and the
     * identity, principal and tenant the sign-in admitted, which the proof
     * found the session records.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $superseded
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function signedIn(
        SignedInSession $session,
        (EloquentSession&Model)|null $superseded,
        ?Tenant $tenant,
        SignInContext $context,
        SignInProof $proof,
        AdmissionRecheck $recheck,
    ): SignInResult {
        $event   = new EventContext($this->context->name(), $context->client, $session->identity, $session->principal, $tenant, $session->record, $session->method);
        $revoked = $superseded === null ? null : new SessionRevoked(
            new EventContext($this->context->name(), $context->client, $session->identity, $session->principal, $tenant, $superseded, $superseded->getSignInMethod()),
            RevocationReason::SUPERSEDED,
        );
        $created  = new SessionCreated($event);
        $signedIn = new SignedIn($event, false);
        $redeemed = $this->redeemed($proof, $context->client, $session->identity, $session->principal, $tenant, $session->record);

        if ($revoked !== null) {
            $this->afterCommit->run($session->record, fn () => $this->context->dispatch($revoked));
        }

        $recheck->signIn($session->record, $session->identity, $session->principal, $tenant);

        $recheck->then($session->record, function () use ($created, $signedIn, $redeemed): void {

            $this->context->dispatch($created);
            $this->context->dispatch($signedIn);

            if ($redeemed === null) {
                return;
            }

            $this->context->dispatch($redeemed);
        });

        return SignInResult::signedIn($session);
    }

    /**
     * The report of an external provider's result redeemed into the session,
     * for a sign-in whose proof is the provider's: its connection and the
     * authorisation request's reference, beside the session's identity,
     * principal and tenant as established; `null` for any other sign-in.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @return ?\SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed
     */
    private function redeemed(
        SignInProof $proof,
        ClientContext $client,
        Identity $identity,
        ?Principal $principal,
        ?Tenant $tenant,
        EloquentSession&Model $record,
    ): ?ExternalResultRedeemed {
        $provenance = $proof->provenance;

        if ($provenance === null) {
            return null;
        }

        $context = new EventContext(
            $this->context->name(),
            $client,
            $identity,
            $principal,
            $tenant,
            $record,
            $proof->method,
            connectionId: $provenance->connectionId,
            requestReference: $proof->requestReference,
        );

        return new ExternalResultRedeemed($context, AuthenticationFlow::SIGN_IN);
    }
}
