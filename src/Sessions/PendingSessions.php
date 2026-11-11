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
 * reads, satisfies, chooses for and discards them.
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
     * The live pending session the credential names, or `null` when the action
     * is not allowed now or the gate would refuse it.
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
     * verified, under the row lock.
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
        // `#[\SensitiveParameter]` does not cover what a closure captures.
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
     * Record the identity's choice of principal and tenant on the pending
     * session, under the row lock.
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
     * Revoke the live pending session the credential names as `signed_out`,
     * returning whether this call ended one.
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
     * may be acted on for the requirement, or why not.
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
     * Why the pending session may not be acted on for the requirement; `null`
     * when it may.
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
     * The principal chosen, with the tenant it is to be active in, or why not.
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
     * Activate the admitted pending session when nothing is outstanding, or
     * keep it pending on what it still waits on.
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
     * Record what the locked pending session now waits on, with its principal
     * and tenant.
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
     * What the pending session's authentication still falls short of, with the
     * first factor it was judged on.
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
     * Describe the pending session.
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
     * The session the sign-in's client proved it holds, while it is still that
     * session as proven; `null` otherwise.
     *
     * One that returned to pending keeps its digest, so its status is checked.
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
     * When the pending session began waiting for what it waits on now.
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
     * Run the work in one transaction, rolling it back when it answers with a
     * refusal.
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
