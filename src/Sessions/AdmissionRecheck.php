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
 * Re-reads what a session newly acts as once one session service call's write
 * commits, and revokes the session when it no longer stands.
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
     * Check a sign-in's new session, active or pending, once its write commits.
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
     * Check a pending session's choice of principal once its write commits.
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
     * Check a switch once its write commits, for the principal or tenant it
     * changed.
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
     * Run a report of the call's write once the check passed, and never once it
     * failed.
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
     * Run a report after the check, whatever it finds.
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
     * The refusal the call answers with when the check failed before it
     * answered, marking the call answered.
     *
     * @return ?\SineMacula\Laravel\Authentication\Admission\Refused
     */
    public function refusal(): ?Refused
    {
        $this->answered = true;

        return $this->refused;
    }

    /**
     * Hold the report while the check waits, or schedule it for the session's
     * commit.
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
     * Run the checks once the session's write commits and the transactions on
     * the subjects' connections have ended.
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
     * Take what the session moved off out of the checks still waiting on it,
     * and return what this call's check judges.
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
     * the waiting reports its verdict allows.
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
     * longer stands, read afresh, or `null` when it does.
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
        $checked = $this->checks['tenant'] ? $tenant : null;

        if ($refusal !== null || $checked === null) {
            return $refusal;
        }

        $tenantId = IdentifierCoercion::stringify($checked->getTenantIdentifier());

        return TenantAdmission::recorded($current, $tenantId, false) instanceof FailureReason ? FailureReason::TENANT_INACTIVE : null;
    }

    /**
     * Why the identity or principal, as read again, no longer stands; `null`
     * when it stands.
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
     * The principal as it is now; `null` when it is gone.
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
     * moved since the call began by a revocation that did not keep the session.
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
     * Revoke the session that failed the check, reporting it once it was handed
     * out, or leave the call the refusal to answer with.
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
