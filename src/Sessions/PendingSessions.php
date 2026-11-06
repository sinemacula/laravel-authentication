<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Context\ContextForgetting;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ProofAcceptance;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Acts on the pending sessions of a guard through their pending credentials:
 * reads one for an action, satisfies its further factor with a proof, records
 * the choice of principal, and discards it.
 *
 * A credential is `<session key>.<secret>`. It names a live pending session of
 * the guard only while the session is this guard's, pending, not revoked and
 * not ended (its idle deadline is the credential's expiry), its digest matches
 * the secret (compared in constant time), the guard's provider returns its very
 * owner, and the principal it records, if any, still resolves through the
 * hinted path as that principal of that owner. Anything else is not found,
 * without saying why. The credential is told apart from every other kind by its
 * path: only these operations read it, and none of them reads a token.
 *
 * Satisfying, choosing and discarding lock the session's row and find it again
 * under the lock, so two calls with one credential serialise: the second finds
 * the session changed and fails as `pending_invalid`. Each runs the gate
 * (`PendingEvaluation`) under the lock: the identity, the method, the principal
 * and its tenant are admitted again, and what the session still waits on is
 * judged again, its proofs and provenance read current (`SessionProofs`), so
 * the session activates, stays pending, or moves on to the choice. Satisfying
 * and choosing, once the action is admitted, also lock the session the
 * sign-in's client proved it holds, whenever the sign-in recorded one, before
 * checking whether an activation may supersede it, and before the session's
 * issuance guard and any read of its proofs: every session row is locked before
 * any proof row, as the package's lock order puts them. A refusal writes
 * nothing (a proof given with it is not stored) and never revokes the session,
 * which waits until its credential expires; only `discard()` ends one early.
 * Once a proof `satisfy()` stored commits, or rolls back, every resolved guard
 * bound to the session forgets the authentication context it holds. A choice
 * has the call's check (`AdmissionRecheck`) read the principal and tenant
 * chosen again once it commits, and the activation's reports wait for it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\PendingLookup Finds the live pending session a credential names. */
    private PendingLookup $lookup;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation  $evaluation
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionActivation  $activation
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $revocations
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     */
    public function __construct(

        /** The context of the guard whose pending sessions are acted on. */
        private GuardContext $context,

        /** The gate a pending session passes each time it is acted on. */
        private PendingEvaluation $evaluation,

        /** Activates a pending session whose every requirement is met. */
        private SessionActivation $activation,

        /** Revokes a discarded pending session and reports it once committed. */
        private RevocationWriter $revocations,

        /** Defers forgetting the authentication contexts of a session until the proof it was given commits or rolls back. */
        private AfterCommit $afterCommit,
    ) {
        $this->lookup = new PendingLookup($context);
    }

    /**
     * The live pending session the credential names, or `null`; with an action,
     * also `null` when its first outstanding requirement does not allow the
     * action now. Also `null` whenever the gate would refuse it: its identity
     * (a machine identity, an inactive one, or one the application no longer
     * admits with the identifier type the sign-in used), its method no longer
     * allowed, or the principal it records, if any, no longer one that may hold
     * it in the active tenant it records (the principal inactive, its own
     * tenant inactive, `ApplicationAccess` refusing it, or that tenant
     * unresolvable, inactive or refused by `TenantAccess`). Such a session can
     * never activate, so nothing (a code sent, an enrolment begun) is done for
     * it. The tenant described is the one the gate admitted. The principals to
     * choose from are listed only while the choice is that requirement. Reads
     * only, on the write connection, with no lock.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Sessions\PendingSession
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function pending(#[\SensitiveParameter] Secret|string $credential, ?PendingAction $action, CarbonImmutable $now): ?PendingSession
    {
        $found = $this->lookup->find($credential, $now, false);

        if ($found === null) {
            return null;
        }

        [$session, $identity, $principal] = $found;

        $requires = $session->getRequires();

        if ($action !== null && !in_array($action, $requires[0]->actions(), true)) {
            return null;
        }

        $refused = $this->evaluation->identityRefusal($identity, $session->getSignInIdentifierType()) !== null
            || !$this->evaluation->allowsMethod((string) $session->getSignInMethod());

        $tenant = $refused || $principal === null ? null : $this->evaluation->recorded($session, $principal);

        if ($refused || $tenant instanceof FailureReason) {
            return null;
        }

        $principals            = $requires[0] === PendingRequirement::PRINCIPAL ? $this->evaluation->principals($identity, $session->getSignInIdentifierType())[0] : [];
        [$outstanding, $first] = in_array(PendingRequirement::MFA, $requires, true)
            ? $this->outstanding($session, $identity, $principal, $tenant, $now)
            : [new Requirement, PendingEvaluation::firstFactorOf($session)];

        return $this->describe($session, $identity, $principal, $tenant, [$requires, $outstanding, $first], $principals);
    }

    /**
     * Satisfy the pending session's further factor with the proof an adapter
     * verified, in one transaction under the row lock: the further factor must
     * be its first outstanding requirement (`pending_action_not_allowed`); the
     * proof must be accepted for it (see
     * `ProofAcceptance::forPendingSession()`: `proof_invalid`,
     * `proof_binding_mismatch`); the gate admits the identity,
     * the method, and the principal and tenant the session records, if any;
     * then the proof is stored, after the session's issuance guard
     * (`IssuanceGuard`), and what the session still waits on is judged again:
     * nothing, and it activates; the further factor still, and it stays
     * pending; or the choice, and it moves on to it, listing the principals. A
     * proof is stored once per call, also when the session stays pending: a
     * verification is single use on the adapter's side. The call's client is
     * the one the activation records and reports; its check has nothing to
     * check, since the session already records what it acts as, which every
     * revocation of those finds.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $call
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function satisfy(#[\SensitiveParameter] Secret|string $credential, ProofResult $proof, CarbonImmutable $now, AdmissionRecheck $call): Refused|SignInResult
    {
        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $held = new \SensitiveParameterValue($credential);

        return $this->atomically(function () use ($held, $proof, $now, $call): Refused|SignInResult {

            $found = $this->lookup->find($held->getValue(), $now, true);

            if ($found === null) {
                return new Refused(FailureReason::PENDING_INVALID);
            }

            [$session, $identity, $principal] = $found;

            $admitted = $this->admitted($session, $identity, $principal, PendingRequirement::MFA, $proof, $now);

            if ($admitted instanceof Refused) {
                return $admitted;
            }

            $proven = $this->proven($session, true);

            IssuanceGuard::hold($session);

            ProofWriter::record($session, $this->context->name(), NewProof::fromResult($proof));

            ContextForgetting::onSettle($this->afterCommit, $session);

            return $this->settle($session, $identity, $principal, $admitted, $now, $proven, $call);
        });
    }

    /**
     * Record the identity's choice of principal on the pending session, and the
     * tenant it is to be active in (the principal's own unless one is named),
     * in one transaction under the row lock: the choice must be its first
     * outstanding requirement (`pending_action_not_allowed`); the gate admits
     * the identity and the method; the principal must be the identity's,
     * resolved through the hinted path as that very one (`principal_mismatch`),
     * and admitted by the application, and the tenant one it may act in and
     * active; then what the session still waits on is judged again: nothing,
     * and it activates as the principal; a further factor (the identity's
     * policy now asks for one), and it records the principal and tenant and
     * waits for it. Either way the principal and the tenant chosen are checked
     * again once the choice commits (`AdmissionRecheck`), and the activation's
     * reports wait for that check: a choice that admitted them before a
     * deactivation or deletion of either committed ends the session instead.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $chosen
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $selection
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $call
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function choose(
        #[\SensitiveParameter] Secret|string $credential,
        Principal $chosen,
        ?TenantSelection $selection,
        CarbonImmutable $now,
        AdmissionRecheck $call,
    ): Refused|SignInResult {
        $held = new \SensitiveParameterValue($credential);

        return $this->atomically(function () use ($held, $chosen, $selection, $now, $call): Refused|SignInResult {

            $found = $this->lookup->find($held->getValue(), $now, true);

            if ($found === null) {
                return new Refused(FailureReason::PENDING_INVALID);
            }

            [$session, $identity] = $found;

            $admitted = $this->admitted($session, $identity, null, PendingRequirement::PRINCIPAL, null, $now);
            $chosenAs = $admitted instanceof Refused ? $admitted : $this->chosen($session, $identity, $chosen, $selection);

            if ($chosenAs instanceof Refused) {
                return $chosenAs;
            }

            [$principal, $tenant] = $chosenAs;

            $call->choice($session, new Admitted($identity, $principal, $tenant));

            return $this->settle($session, $identity, $principal, $tenant, $now, $this->proven($session, true), $call);
        });
    }

    /**
     * End the live pending session the credential names: revoke it as
     * `signed_out`, under the row lock, and report `SessionRevoked` once
     * committed, for the client given. Returns whether the credential named
     * one, which this call ended.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function discard(#[\SensitiveParameter] Secret|string $credential, CarbonImmutable $now, ClientContext $client): bool
    {
        $held = new \SensitiveParameterValue($credential);

        return SessionLookup::model()->getConnection()->transaction(function () use ($held, $now, $client): bool {

            $found = $this->lookup->find($held->getValue(), $now, true);

            if ($found === null) {
                return false;
            }

            [$session, $identity, $principal] = $found;

            $event = new SessionRevoked(
                new EventContext($this->context->name(), $client, $identity, $principal, session: $session, method: $session->getSignInMethod()),
                RevocationReason::SIGNED_OUT,
            );

            return $this->revocations->revoke($session, RevocationReason::SIGNED_OUT, $now, fn () => $this->context->dispatch($event));
        });
    }

    /**
     * The tenant the pending session records, admitted again, when the session
     * may be acted on for the requirement: the requirement is its
     * first outstanding one; a proof, when one is given, is accepted for it;
     * the identity is admitted with the identifier type the sign-in used and
     * the method is still allowed; and the principal it records, if any, may
     * still hold it in that tenant. Otherwise why not.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement  $requirement
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Contracts\Tenant|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function admitted(
        EloquentSession&Model $session,
        Identity $identity,
        ?Principal $principal,
        PendingRequirement $requirement,
        ?ProofResult $proof,
        CarbonImmutable $now,
    ): Refused|Tenant|null {
        $refusal = $this->actionRefusal($session, $requirement, $proof, $now)
            ?? $this->evaluation->identityRefusal($identity, $session->getSignInIdentifierType())
            ?? ($this->evaluation->allowsMethod((string) $session->getSignInMethod()) ? null : FailureReason::METHOD_NOT_ALLOWED);

        $tenant = $refusal === null && $principal !== null ? $this->evaluation->recorded($session, $principal) : null;

        return match (true) {
            $refusal !== null                => new Refused($refusal, $identity, $principal, session: $session),
            $tenant instanceof FailureReason => new Refused($tenant, $identity, $principal, session: $session),
            default                          => $tenant,
        };
    }

    /**
     * Why the pending session may not be acted on for the requirement: it is
     * not the first outstanding one, or the proof given is not accepted for
     * it; `null` when it may.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement  $requirement
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private function actionRefusal(EloquentSession&Model $session, PendingRequirement $requirement, ?ProofResult $proof, CarbonImmutable $now): ?FailureReason
    {
        if ($session->getRequires()[0] !== $requirement) {
            return FailureReason::PENDING_ACTION_NOT_ALLOWED;
        }

        return $proof === null ? null : ProofAcceptance::forPendingSession($proof, $session, $this->context->name(), self::waitingSince($session), $now);
    }

    /**
     * The principal chosen, as the identity's own principal the application
     * admits, with the tenant it is to be active in; or why not.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $chosen
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $selection
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Principal, 1: ?\SineMacula\Laravel\Authentication\Contracts\Tenant}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function chosen(EloquentSession&Model $session, Identity $identity, Principal $chosen, ?TenantSelection $selection): array|Refused
    {
        $principal = $this->evaluation->named($identity, $chosen);

        if ($principal instanceof FailureReason) {
            return new Refused($principal, $identity, session: $session);
        }

        $tenant = $this->evaluation->destination($principal, $selection);

        return $tenant instanceof FailureReason ? new Refused($tenant, $identity, $principal, session: $session) : [$principal, $tenant];
    }

    /**
     * Judge what the admitted pending session still waits on, and act on it:
     * with a principal, the tenant's authentication policy is asked first, and
     * a session it requires to be established through a connection is refused
     * (`sso_required`), while a further factor it requires is owed as the
     * identity's own is; activate it, recording the policy's version, when
     * nothing is outstanding; otherwise keep it pending, writing what it waits
     * on (and the principal and tenant it records) when that changed, and
     * listing the principals to choose from when the choice is now first. A
     * session left with the choice and no principal to choose from is refused
     * with the reason the last was refused, or `principal_unresolved`. The
     * factor policy is told of the session the sign-in's client proved it
     * holds, as the caller found it still is; when that session changed before
     * the activation could supersede it, the session is judged again without
     * it, factor policy included.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \Carbon\CarbonImmutable  $now
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $proven
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $call
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function settle(
        EloquentSession&Model $session,
        Identity $identity,
        ?Principal $principal,
        ?Tenant $tenant,
        CarbonImmutable $now,
        (EloquentSession&Model)|null $proven,
        AdmissionRecheck $call,
    ): Refused|SignInResult {
        $policy = $this->evaluation->tenantPolicy($identity, $principal, $tenant, $session, $now, current: true);

        if ($policy->standing === TenantPolicyStanding::SSO_REQUIRED) {
            return new Refused(FailureReason::SSO_REQUIRED, $identity, $principal, $tenant, $session);
        }

        $first       = PendingTransitions::firstFactorOf($session, $policy, current: true);
        $outstanding = Requirement::strictest($this->evaluation->owedFactorOn($session, $identity, $first, $proven, $now, current: true), $policy->factor);
        $requires    = PendingEvaluation::requirements($outstanding, $principal);

        if ($principal !== null && $requires === []) {
            $destination = new Admitted($identity, $principal, $tenant);
            $activated   = $this->activation->activate($session, $destination, $policy->version, $call, $now, $proven);

            return $activated === null
                ? $this->settle($session, $identity, $principal, $tenant, $now, null, $call)
                : SignInResult::signedIn($activated);
        }

        [$principals, $refusal] = $requires[0] === PendingRequirement::PRINCIPAL ? $this->evaluation->principals($identity, $session->getSignInIdentifierType()) : [[], null];

        if ($requires[0] === PendingRequirement::PRINCIPAL && $principals === []) {
            return new Refused($refusal ?? FailureReason::PRINCIPAL_UNRESOLVED, $identity, session: $session);
        }

        if ($requires !== $session->getRequires()) {
            $this->wait($session, $principal, $tenant, $requires);
        }

        return SignInResult::pending($this->describe($session, $identity, $principal, $tenant, [$requires, $outstanding, $first], $principals));
    }

    /**
     * Record what the locked pending session now waits on, and the principal
     * and tenant it records, and mirror it on the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>  $requires
     * @return void
     *
     * @throws \JsonException
     */
    private function wait(EloquentSession&Model $session, ?Principal $principal, ?Tenant $tenant, array $requires): void
    {
        [$type, $id] = PrincipalReference::columns($session);

        $values = [
            $session->getRequiresName() => PendingState::requires($requires),
            $type                       => $principal === null ? null : PrincipalReference::type($principal),
            $id                         => $principal === null ? null : PrincipalReference::id($principal),
            $session->getTenantIdName() => IdentifierCoercion::stringify($tenant?->getTenantIdentifier()),
        ];

        $session->getConnection()->table($session->getTable())->where($session->getKeyName(), $session->getKey())->update($values);

        PendingState::mirror($session, $values);
    }

    /**
     * What the pending session's authentication still falls short of, the
     * strictest of the identity-level requirement while it is owed and the
     * requirement of the tenant it records while that is unmet, with the first
     * factor both were judged on, read once.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \SineMacula\Laravel\Authentication\Requirements\Requirement, 1: \SineMacula\Laravel\Authentication\Proofs\RecordedProof}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function outstanding(EloquentSession&Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant, CarbonImmutable $now): array
    {
        $policy = $this->evaluation->tenantPolicy($identity, $principal, $tenant, $session, $now);
        $first  = PendingTransitions::firstFactorOf($session, $policy);
        $owed   = $this->evaluation->owedFactorOn($session, $identity, $first, $this->proven($session), $now);

        return [Requirement::strictest($owed, $policy->factor), $first];
    }

    /**
     * Describe the pending session, with what it waits on, what its
     * authentication still falls short of, its first factor, and the principals
     * to choose from while the choice is its first requirement.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  array{0: non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>, 1: \SineMacula\Laravel\Authentication\Requirements\Requirement, 2: \SineMacula\Laravel\Authentication\Proofs\RecordedProof}  $waiting
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingSession
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     */
    private function describe(EloquentSession&Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant, array $waiting, array $principals): PendingSession
    {
        [$requires, $outstanding, $first] = $waiting;

        $expiresAt = $session->getIdleExpiresAt() ?? throw new \LogicException('A pending session the package wrote always records when its credential expires.');

        return new PendingSession(
            $session->getSessionIdentifier(),
            $this->context->name(),
            $identity,
            $principal,
            $tenant,
            $requires,
            (string) $session->getSignInMethod(),
            CarbonImmutable::instance($expiresAt),
            $session,
            $outstanding,
            $first,
            $principals,
        );
    }

    /**
     * The session the sign-in's client proved it holds, when it still is that
     * session as proven: of this guard and owner, active, unrevoked, and
     * holding the refresh digest it was proven against; else `null`. One that
     * returned to pending keeps that digest, so its status is checked too. With
     * `$lock`, its row is read locked until the transaction ends, before any of
     * these checks, so the activation's supersede that may follow takes no row
     * after them; a session that proved none locks nothing.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  bool  $lock
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function proven(EloquentSession&Model $session, bool $lock = false): (EloquentSession&Model)|null
    {
        $digest = $session->getAttribute($session->getSupersedesRefreshKeyName());
        $id     = $session->getAttribute($session->getSupersedesSessionIdName());
        $proven = match (true) {
            !is_string($digest) => null,
            $lock               => SessionLookup::lock($id),
            default             => SessionLookup::find($id),
        };

        if ($proven === null) {
            return null;
        }

        $guard = $this->context->name();
        $still = WriteConnection::during($proven, static function () use ($proven, $session, $digest, $guard): bool {

            $unchanged = $proven->getStatus() === SessionStatus::ACTIVE && $proven->getRevokedAt() === null && $proven->getRefreshKey() === $digest;

            return $unchanged && $proven->getGuard() === $guard && SessionOwnership::ownerKey($proven) === SessionOwnership::ownerKey($session);
        });

        return $still ? $proven : null;
    }

    /**
     * When the pending session began waiting for what it waits on now: the
     * later of its start and its last change of context (a return to pending
     * moves it), so no proof made before then satisfies it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Carbon\CarbonImmutable
     *
     * @throws \LogicException
     */
    private static function waitingSince(EloquentSession&Model $session): CarbonImmutable
    {
        $started  = $session->getSignedInAt()?->getTimestamp() ?? 0;
        $switched = $session->getSwitchedAt()?->getTimestamp() ?? 0;

        return CarbonImmutable::createFromTimestamp(max($started, $switched));
    }

    /**
     * Run the work in one transaction on the session model's connection,
     * committing what it wrote unless it answers with a refusal, which rolls
     * back everything it wrote, the proof it stored among it; an exception
     * rolls back too, and is thrown on. Inside a caller's transaction a
     * deadlock, serialisation failure or lock wait timeout is thrown on as
     * Laravel's `DeadlockException` with the caller's transaction level
     * restored (on MySQL and MariaDB a deadlock has already rolled the caller's
     * whole transaction back, its savepoints with it), for the caller to roll
     * back and retry whole.
     *
     * @param  \Closure(): (\SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult)  $work
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function atomically(\Closure $work): Refused|SignInResult
    {
        try {
            return SessionLookup::model()->getConnection()->transaction(static function () use ($work): SignInResult {

                $outcome = $work();

                return $outcome instanceof Refused ? throw new PendingActionRefused($outcome) : $outcome;
            });
        } catch (PendingActionRefused $refusal) {
            return $refusal->refused;
        }
    }
}
