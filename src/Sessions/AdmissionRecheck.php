<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
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
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * One call of the session service that makes a session act as an identity,
 * principal or tenant it did not act as before (a sign-in's session, active or
 * pending; a pending session's choice of principal; a switch to another
 * principal or tenant), and the check that call's write is held to once it is
 * committed: what the session newly acts as is read again, afresh, and judged
 * on its standing alone.
 *
 * A sign-in, a choice or a switch admits what the session acts as long before
 * it writes the session, so a deactivation or a deletion that commits between
 * the two is followed by a revocation that finds no session to end, and the
 * session it then writes would work again once the subject is reactivated or
 * restored. The check closes that window: it runs once the write is committed
 * and no transaction is open on the session's connection or on any connection
 * the identity, principal or tenant lives on, so it reads each as committed,
 * never through a snapshot taken before. An identity is reloaded through the
 * guard's provider and must still be that identity (`identity_deleted`) and
 * active (`identity_deactivated`); a principal is resolved again through the
 * guard's resolver, with its identifier as the hint, and must still be that
 * principal (`principal_deleted`), active (`principal_deactivated`) and in an
 * active tenant of its own (`tenant_deactivated`); the active tenant the
 * session records must still resolve for the principal and be active
 * (`tenant_deactivated`). An identity or principal that records a "tokens valid
 * after" cutoff (`HasTokensValidAfter`) is also held to it: a cutoff moved
 * strictly after the second the call began is the trace of a bulk revocation
 * that ran while the call was in flight (one that a reactivation or restore
 * since undid, among them), which the session would otherwise outlive
 * (`signed_out_everywhere`). Nothing an access contract, the application policy
 * or a tenant's authentication policy says is asked again: those are not what a
 * deactivation or deletion changes.
 *
 * A session that fails the check is revoked with the reason, by the conditional
 * revocation every other one uses, so one already revoked keeps its first
 * reason. The reports the call scheduled through `then()` run only once the
 * check passed, after it, in order, and never once it failed. A check that
 * failed before the call answered makes the call answer the refusal instead
 * (`refusal()`), and a new session the call never handed out is revoked without
 * a `SessionRevoked`; one that failed after (the call ran inside a caller's
 * transaction, so the check waited for its commit), or a session that existed
 * before the call (a choice's, a switch's), is reported as revoked, and a guard
 * bound to it forgets it. A call that wrote nothing to check (`satisfy()`, a
 * switch that changed neither principal nor tenant) schedules its reports as
 * `AfterCommit` would.
 *
 * One instance is one call: it holds the client the call is for and the second
 * it began, taken before anything was verified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AdmissionRecheck
{
    /** @var array{identity: bool, principal: bool, tenant: bool} What the session newly acts as, and so is read again. */
    private array $checks = ['identity' => false, 'principal' => false, 'tenant' => false];

    /** @var bool Whether the call wrote a session to check. */
    private bool $watched = false;

    /** @var bool Whether the session is one the call itself created, never handed out before the call answers. */
    private bool $created = false;

    /** @var ?bool Whether the check passed; `null` while it has not run. */
    private ?bool $passed = null;

    /** @var list<\Closure(): void> The reports waiting for the check to pass. */
    private array $waiting = [];

    /** @var bool Whether the call has answered. */
    private bool $answered = false;

    /** @var ?\SineMacula\Laravel\Authentication\Admission\Refused The refusal a check that failed before the call answered leaves it to answer with. */
    private ?Refused $refused = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $revocations
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Carbon\CarbonImmutable  $began
     */
    public function __construct(

        /** The context of the guard whose provider and resolver read the subjects again. */
        private readonly GuardContext $context,

        /** The guard's bound state, which forgets a session that fails the check. */
        private readonly GuardBinding $binding,

        /** Revokes a session that fails the check. */
        private readonly RevocationWriter $revocations,

        /** Defers the check until the writes it reads past are committed. */
        private readonly AfterCommit $afterCommit,

        /** The client the call is for, which a revocation the check makes is reported with. */
        public readonly ClientContext $client,

        /** When the call began, to the second, before anything was verified. */
        public readonly CarbonImmutable $began,
    ) {}

    /**
     * Check a sign-in's new session, active or pending, once its write commits:
     * its identity, the principal it acts as (none while a choice is
     * outstanding) and the active tenant it records.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     */
    public function signIn(EloquentSession&Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant): void
    {
        $this->created = true;

        $this->watch($session, $identity, $principal, $tenant, ['identity' => true, 'principal' => $principal !== null, 'tenant' => $tenant !== null]);
    }

    /**
     * Check a pending session's choice once its write commits: the principal
     * chosen and the active tenant it is to act in. The identity is the one the
     * pending session already records, which every revocation of it finds.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $chosen
     * @return void
     */
    public function choice(EloquentSession&Model $session, Admitted $chosen): void
    {
        $this->watch($session, $chosen->identity, $chosen->principal, $chosen->tenant, ['identity' => false, 'principal' => true, 'tenant' => $chosen->tenant !== null]);
    }

    /**
     * Check a switch once its write commits, for what it changed: the
     * destination principal when the session acted as another, and the
     * destination tenant when it acted in another. A switch that changes
     * neither is checked for nothing.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  bool  $principal
     * @param  bool  $tenant
     * @return void
     */
    public function switch(EloquentSession&Model $session, Admitted $destination, bool $principal, bool $tenant): void
    {
        if (!$principal && !$tenant) {
            return;
        }

        $checks = ['identity' => false, 'principal' => $principal, 'tenant' => $tenant && $destination->tenant !== null];

        $this->watch($session, $destination->identity, $destination->principal, $destination->tenant, $checks);
    }

    /**
     * Run a report of the call's write once the check passed, after it: at once
     * when it already did, at its end while it waits, never once it failed.
     * With nothing watched, once the writes on the session's connection commit,
     * as `AfterCommit` runs it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \Closure(): void  $report
     * @return void
     */
    public function then(Model $session, \Closure $report): void
    {
        if ($this->watched && $this->passed === null) {

            $this->waiting[] = $report;

            return;
        }

        if ($this->passed === false) {
            return;
        }

        $this->afterCommit->run($session, $report);
    }

    /**
     * The refusal the call answers with in place of what it wrote, when the
     * check failed before it answered; `null` otherwise. The call has answered
     * once asked: a check that fails after reports the revocation it makes.
     *
     * @return ?\SineMacula\Laravel\Authentication\Admission\Refused
     */
    public function refusal(): ?Refused
    {
        $this->answered = true;

        return $this->refused;
    }

    /**
     * Watch the session for the checks: run them once the writes on the
     * session's connection, and then on each connection the subjects live on,
     * have committed (at once on one with no transaction open), and the reports
     * waiting after them when they pass.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  array{identity: bool, principal: bool, tenant: bool}  $checks
     * @return void
     */
    private function watch(EloquentSession&Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant, array $checks): void
    {
        $this->watched = true;
        $this->checks  = $checks;

        $subjects = array_filter([$session, $identity, $principal, $tenant], static fn (?object $subject): bool => $subject instanceof Model);

        $this->afterCommit->runAcross(array_values($subjects), fn () => $this->settle($session, $identity, $principal, $tenant));
    }

    /**
     * Judge the committed session, then run the reports waiting for it, or end
     * it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     *
     * @throws \Throwable
     */
    private function settle(EloquentSession&Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant): void
    {
        $reason  = $this->judge($identity, $principal, $tenant);
        $waiting = $this->waiting;

        $this->passed  = $reason === null;
        $this->waiting = [];

        if ($reason !== null) {

            $this->end($reason, $session, $identity, $principal, $tenant);

            return;
        }

        foreach ($waiting as $report) {
            $report();
        }
    }

    /**
     * Why what the session acts as no longer stands, read afresh, or `null`
     * when it does.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Throwable
     */
    private function judge(Identity $identity, ?Principal $principal, ?Tenant $tenant): ?FailureReason
    {
        $current = $this->checks['identity'] ? $this->reload($identity) : $identity;

        if ($current === null) {
            return FailureReason::IDENTITY_UNKNOWN;
        }

        $refusal = $this->checks['identity'] ? $this->standing($current, FailureReason::IDENTITY_INACTIVE) : null;

        return $refusal ?? ($principal === null ? null : $this->judgePrincipal($current, $principal, $tenant));
    }

    /**
     * Why the principal, or the active tenant, the session acts as and in no
     * longer stands, read afresh, or `null` when it does.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Throwable
     */
    private function judgePrincipal(Identity $identity, Principal $principal, ?Tenant $tenant): ?FailureReason
    {
        $current = $this->current($identity, $principal);
        $refusal = match (true) {
            !$this->checks['principal'] => null,
            $current === null           => FailureReason::PRINCIPAL_UNRESOLVED,
            default                     => $this->standing($current, FailureReason::PRINCIPAL_INACTIVE),
        };

        if ($refusal !== null || !$this->checks['tenant']) {
            return $refusal;
        }

        $tenantId = IdentifierCoercion::stringify($tenant?->getTenantIdentifier());

        return TenantAdmission::recorded($current ?? $principal, $tenantId, false) instanceof FailureReason ? FailureReason::TENANT_INACTIVE : null;
    }

    /**
     * Why the identity or principal, as read again, no longer stands: inactive
     * (the reason given), a principal's own tenant inactive or no longer
     * loadable (`tenant_inactive`), or a "tokens valid after" cutoff moved
     * since the call began (`issued_before_cutoff`); `null` when it stands.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Contracts\Principal  $subject
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $inactive
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private function standing(Identity|Principal $subject, FailureReason $inactive): ?FailureReason
    {
        return match (true) {
            !ActivationPolicy::isActive($subject)                                               => $inactive,
            $subject instanceof Principal && ActivationPolicy::activeTenant($subject) === false => FailureReason::TENANT_INACTIVE,
            $this->isCutOff($subject)                                                           => FailureReason::ISSUED_BEFORE_CUTOFF,
            default                                                                             => null,
        };
    }

    /**
     * The principal as it is now: for an identity that is its own principal,
     * the identity read again; otherwise the principal the guard's resolver
     * answers for its identifier, when it is that very principal; `null` when
     * it is gone.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function current(Identity $identity, Principal $principal): ?Principal
    {
        if ($principal instanceof Identity && SessionPreconditions::isSameIdentity($principal, $identity)) {

            $reloaded = $this->checks['identity'] ? $identity : $this->reload($identity);

            return $reloaded instanceof Principal ? $reloaded : null;
        }

        $resolved = $this->context->resolver()->resolve($identity, PrincipalReference::id($principal));

        return $resolved !== null
            && PrincipalReference::type($resolved) === PrincipalReference::type($principal)
            && IdentifierCoercion::matches(PrincipalReference::id($resolved), PrincipalReference::id($principal))
            ? $resolved
            : null;
    }

    /**
     * The identity read again through the guard's provider, when the provider
     * still answers with that very identity; `null` when it is gone.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function reload(Identity $identity): ?Identity
    {
        $reloaded = $this->context->provider()->retrieveById($identity->getAuthIdentifier());

        return $reloaded instanceof Identity && SessionPreconditions::isSameIdentity($reloaded, $identity) ? $reloaded : null;
    }

    /**
     * Whether the identity or principal records a "tokens valid after" cutoff
     * moved strictly after the second the call began.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Contracts\Principal  $holder
     * @return bool
     *
     * @throws \LogicException
     */
    private function isCutOff(Identity|Principal $holder): bool
    {
        if (!$holder instanceof HasTokensValidAfter) {
            return false;
        }

        $cutoff = WriteConnection::during($holder, static fn () => $holder->getTokensValidAfter());

        return $cutoff !== null && $cutoff->getTimestamp() > $this->began->getTimestamp();
    }

    /**
     * End the session that failed the check: revoke it with the reason's
     * revocation reason, then report the revocation and forget a binding to it
     * when the session was handed out (it existed before the call, or the call
     * has answered), or leave the call the refusal to answer with when it has
     * not answered yet.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     */
    private function end(FailureReason $reason, EloquentSession&Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant): void
    {
        $revoked   = self::revocationReason($reason);
        $context   = new EventContext($this->context->name(), $this->client, $identity, $principal, $tenant, $session, $session->getSignInMethod());
        $handedOut = $this->answered || !$this->created;

        if (!$this->answered) {
            $this->refused = new Refused($reason, $identity, $principal, $tenant);
        }

        $this->revocations->revoke(
            $session,
            $revoked,
            CarbonImmutable::now()->startOfSecond(),
            $handedOut ? fn () => $this->context->dispatch(new SessionRevoked($context, $revoked)) : static fn () => null,
        );

        if (!$handedOut) {
            return;
        }

        $this->binding->forgetSession($session);
    }

    /**
     * The reason a session that failed the check is revoked with.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason
     */
    private static function revocationReason(FailureReason $reason): RevocationReason
    {
        return match ($reason) {
            FailureReason::IDENTITY_UNKNOWN     => RevocationReason::IDENTITY_DELETED,
            FailureReason::IDENTITY_INACTIVE    => RevocationReason::IDENTITY_DEACTIVATED,
            FailureReason::PRINCIPAL_UNRESOLVED => RevocationReason::PRINCIPAL_DELETED,
            FailureReason::PRINCIPAL_INACTIVE   => RevocationReason::PRINCIPAL_DEACTIVATED,
            FailureReason::TENANT_INACTIVE      => RevocationReason::TENANT_DEACTIVATED,
            default                             => RevocationReason::SIGNED_OUT_EVERYWHERE,
        };
    }
}
