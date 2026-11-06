<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
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
 * on the session's connection and the transaction open on each connection the
 * identity, principal or tenant model lives on has ended, committed or rolled
 * back, so it reads each such model as committed, never through a snapshot
 * taken before. What it reads on another connection (a principal or tenant that
 * is no Eloquent model, through its resolver; a principal's own tenant loaded
 * from elsewhere; activity derived from other rows) is read as that connection
 * gives it. An identity is reloaded through the guard's provider and must still
 * be that identity (`identity_deleted`) and active (`identity_deactivated`); a
 * principal the session newly acts as is resolved again through the guard's
 * resolver, with its identifier as the hint, and must still be that principal
 * (`principal_deleted`), active (`principal_deactivated`) and in an active
 * tenant of its own (`tenant_deactivated`); the active tenant the session newly
 * records must still resolve for the principal and be active
 * (`tenant_deactivated`). An identity or principal that records a "tokens valid
 * after" cutoff (`HasTokensValidAfter`) is also held to it: a cutoff moved
 * strictly after the second the call began is the trace of a bulk revocation
 * that ran while the call was in flight (one that a reactivation or restore
 * since undid, among them), which the session would otherwise outlive
 * (`signed_out_everywhere`), unless a revocation that kept the session (as a
 * password change keeps the current one) moved it there: that one saw the
 * session (`KeptSessions`). A switch of the active tenant alone still needs its
 * principal to resolve, since the tenant is resolved through it. A check judges
 * only the principal and tenant the session still acts as and in: a later
 * switch or choice of the same session, while the check still waits, takes
 * those it changed out of it (`WatchedSessions`), and judges an active tenant
 * the session keeps under another principal in its place. Nothing an access
 * contract, the application policy or a tenant's authentication policy says is
 * asked again: those are not what a deactivation or deletion changes.
 *
 * A session that fails the check is revoked with the reason, by the conditional
 * revocation every other one uses, so one already revoked keeps its first
 * reason. The reports the call scheduled through `then()` run only once the
 * check passed, after it, in order, and never once it failed; those scheduled
 * through `afterCheck()` (a revocation the call made of another session) run
 * after it in the same order whatever it found, so a listener that throws on
 * one cannot keep the check from running; nor can one that throws on a report
 * of another call committed with it, since the check is required work
 * (`AfterCommit`). A check that failed before the call answered makes the call
 * answer the refusal instead (`refusal()`), and a new session the call never
 * handed out is revoked without a `SessionRevoked`; one that failed after (the
 * call ran inside a caller's transaction, so the check waited for its commit),
 * or a session that existed before the call (a choice's, a switch's), is
 * reported as revoked, and a guard bound to it forgets it; the refusal a choice
 * or a switch answers names that session. A call that wrote nothing to check
 * (`satisfy()`, a switch that changed neither principal nor tenant) schedules
 * its reports as `AfterCommit` would.
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

    /** @var list<array{0: \Closure(): void, 1: bool}> The reports waiting for the check, each with whether it runs only once the check passed. */
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
        $this->watch($session, $chosen->identity, $chosen->principal, $chosen->tenant, $this->moveOn($session, true, true, $chosen->tenant));
    }

    /**
     * Check a switch once its write commits, for what it changed: the
     * destination principal when the session acted as another, and the
     * destination tenant when it acted in another (not a switch to no tenant,
     * which leaves nothing to deactivate), or when a check still waiting on the
     * session was to judge it through the principal the session left.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  bool  $principal
     * @param  bool  $tenant
     * @return void
     */
    public function switch(EloquentSession&Model $session, Admitted $destination, bool $principal, bool $tenant): void
    {
        $checks = $this->moveOn($session, $principal, $tenant, $destination->tenant);

        if (!$checks['principal'] && !$checks['tenant']) {
            return;
        }

        $this->watch($session, $destination->identity, $destination->principal, $destination->tenant, $checks);
    }

    /**
     * Run a report of the call's write, or anything else only a session that
     * stands is owed (the attempt-limit slots a sign-in gives back), once the
     * check passed, after it: at once when it already did, at its end while it
     * waits, never once it failed. With nothing watched, once the writes on the
     * session's connection commit, as `AfterCommit` runs it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \Closure(): void  $report
     * @return void
     */
    public function then(Model $session, \Closure $report): void
    {
        $this->schedule($session, $report, true);
    }

    /**
     * Run a report that stands whatever the check finds (a revocation the call
     * made of another session) after the check, in order with the reports
     * waiting for it: at its end while it waits, otherwise once the writes on
     * the session's connection commit, as `AfterCommit` runs it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \Closure(): void  $report
     * @return void
     */
    public function afterCheck(Model $session, \Closure $report): void
    {
        $this->schedule($session, $report, false);
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
     * Hold the report until the check has run while it waits, or schedule it
     * for the session's commit, unless it runs only once the check passed and
     * the check failed.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \Closure(): void  $report
     * @param  bool  $gated
     * @return void
     */
    private function schedule(Model $session, \Closure $report, bool $gated): void
    {
        if ($this->watched && $this->passed === null) {

            $this->waiting[] = [$report, $gated];

            return;
        }

        if ($gated && $this->passed === false) {
            return;
        }

        $this->afterCommit->run($session, $report);
    }

    /**
     * Watch the session for the checks: run them once the writes on the
     * session's connection have committed, and then once the transaction open
     * on each connection the subjects live on has ended, committed or rolled
     * back (at once on one with no transaction open), and the reports waiting
     * after them when they pass. Only the session's own connection decides
     * whether the session is durable; the subjects' are waited for only so they
     * are not read through a snapshot taken before.
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

        $watching = self::watching();

        $watching->watch($session, $this);

        $this->afterCommit->runIfRolledBack($session, fn () => $watching->forget($session, $this));

        $subjects = array_values(array_filter([$identity, $principal, $tenant], static fn (?object $subject): bool => $subject instanceof Model));

        $this->afterCommit->runAcross([$session], fn () => $this->afterCommit->runOnceEnded($subjects, fn () => $this->settle($session, $identity, $principal, $tenant)));
    }

    /**
     * Tell the checks still waiting to judge the session that it no longer acts
     * as the principal they were written for (when `$principal`), or in the
     * tenant (when `$tenant`), so they leave those out, unless this call's
     * write rolls back, and return what this call's check judges: the principal
     * when it changed, and the tenant moved to (none leaves nothing to
     * deactivate) when it changed, or when a check still waiting was to judge
     * it as the principal the session left.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  bool  $principal
     * @param  bool  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $to
     * @return array{identity: bool, principal: bool, tenant: bool}
     */
    private function moveOn(Model $session, bool $principal, bool $tenant, ?Tenant $to): array
    {
        $handedOver = false;

        foreach (self::watching()->of($session) as $earlier) {

            $checks     = $earlier->checks;
            $handedOver = $handedOver || ($checks['tenant'] && $principal && !$tenant);

            $earlier->checks = [
                'identity'  => $checks['identity'],
                'principal' => $checks['principal'] && !$principal,
                'tenant'    => $checks['tenant']    && !$principal && !$tenant,
            ];

            $this->afterCommit->runIfRolledBack($session, static function () use ($earlier, $checks): void {
                $earlier->checks = $checks;
            });
        }

        return ['identity' => false, 'principal' => $principal, 'tenant' => $to !== null && ($tenant || $handedOver)];
    }

    /**
     * Judge the committed session, ending it when it no longer stands, then run
     * the reports waiting for the check that its verdict lets run.
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
        self::watching()->forget($session, $this);

        $reason  = $this->judge($session, $identity, $principal, $tenant);
        $waiting = $this->waiting;

        $this->passed  = $reason === null;
        $this->waiting = [];

        if ($reason !== null) {
            $this->end($reason, $session, $identity, $principal, $tenant);
        }

        foreach ($waiting as [$report, $gated]) {

            if ($gated && $reason !== null) {
                continue;
            }

            $report();
        }
    }

    /**
     * Why what the session acts as no longer stands, read afresh, or `null`
     * when it does.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Throwable
     */
    private function judge(Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant): ?FailureReason
    {
        $current = $this->checks['identity'] ? $this->reload($identity) : $identity;

        if ($current === null) {
            return FailureReason::IDENTITY_UNKNOWN;
        }

        $refusal = $this->checks['identity'] ? $this->standing($session, $current, FailureReason::IDENTITY_INACTIVE) : null;
        $judged  = $this->checks['principal'] || $this->checks['tenant'] ? $principal : null;

        return $refusal ?? ($judged === null ? null : $this->judgePrincipal($session, $current, $judged, $tenant));
    }

    /**
     * Why the principal, or the active tenant, the session acts as and in no
     * longer stands, read afresh, or `null` when it does. The principal is read
     * again for a check of the active tenant alone (a switch of tenant) too,
     * though its own standing is not judged then: the active tenant is resolved
     * through it (its own tenant, when that is the one named), and the instance
     * the call admitted may hold that tenant as it was loaded before the
     * change. So a principal that is gone ends the session whatever is checked:
     * there is nothing current to resolve the tenant through.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Throwable
     */
    private function judgePrincipal(Model $session, Identity $identity, Principal $principal, ?Tenant $tenant): ?FailureReason
    {
        $current = $this->current($identity, $principal);

        if ($current === null) {
            return FailureReason::PRINCIPAL_UNRESOLVED;
        }

        $refusal = $this->checks['principal'] ? $this->standing($session, $current, FailureReason::PRINCIPAL_INACTIVE) : null;

        if ($refusal !== null || !$this->checks['tenant']) {
            return $refusal;
        }

        $tenantId = IdentifierCoercion::stringify($tenant?->getTenantIdentifier());

        return TenantAdmission::recorded($current, $tenantId, false) instanceof FailureReason ? FailureReason::TENANT_INACTIVE : null;
    }

    /**
     * Why the identity or principal, as read again, no longer stands: inactive
     * (the reason given), a principal's own tenant inactive or no longer
     * loadable (`tenant_inactive`), or a "tokens valid after" cutoff moved
     * since the call began (`issued_before_cutoff`); `null` when it stands.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Contracts\Principal  $subject
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $inactive
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private function standing(Model $session, Identity|Principal $subject, FailureReason $inactive): ?FailureReason
    {
        return match (true) {
            !ActivationPolicy::isActive($subject)                                               => $inactive,
            $subject instanceof Principal && ActivationPolicy::activeTenant($subject) === false => FailureReason::TENANT_INACTIVE,
            $this->isCutOff($session, $subject)                                                 => FailureReason::ISSUED_BEFORE_CUTOFF,
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
     * moved strictly after the second the call began, and after any cutoff a
     * revocation that kept the session moved for it (`KeptSessions`): such a
     * revocation saw the session, so its cutoff is no trace of one that could
     * not.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Contracts\Principal  $holder
     * @return bool
     *
     * @throws \LogicException
     */
    private function isCutOff(Model $session, Identity|Principal $holder): bool
    {
        if (!$holder instanceof HasTokensValidAfter) {
            return false;
        }

        $cutoff = WriteConnection::during($holder, static fn () => $holder->getTokensValidAfter());
        $floor  = Container::getInstance()->make(KeptSessions::class)->floor($session, $holder, $this->began);

        return $cutoff !== null && $cutoff->getTimestamp() > $floor->getTimestamp();
    }

    /**
     * End the session that failed the check: revoke it with the reason's
     * revocation reason, then report the revocation and forget a binding to it
     * (even when a listener of the report throws) when the session was handed
     * out (it existed before the call, or the call has answered), or leave the
     * call the refusal to answer with when it has not answered yet.
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
            $this->refused = new Refused($reason, $identity, $principal, $tenant, $this->created ? null : $session);
        }

        if (!$handedOut) {

            $this->revocations->revoke($session, $revoked, CarbonImmutable::now()->startOfSecond(), static fn () => null);

            return;
        }

        try {
            $this->revocations->revoke($session, $revoked, CarbonImmutable::now()->startOfSecond(), fn () => $this->context->dispatch(new SessionRevoked($context, $revoked)));
        } finally {
            $this->binding->forgetSession($session);
        }
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

    /**
     * The checks of the request or job still waiting, per session.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\WatchedSessions
     */
    private static function watching(): WatchedSessions
    {
        return Container::getInstance()->make(WatchedSessions::class);
    }
}
