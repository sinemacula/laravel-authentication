<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Context\ContextForgetting;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Factors\FactorReference;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;

/**
 * Ends sessions when the factor package removes, changes or resets an
 * identity's factors, and judges the current session again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorRevocations
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionRevocations  $revocations
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingTransitions  $transitions
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose current session is judged again. */
        private GuardContext $context,

        /** The guard's bound state, forgotten when the current session stops being active. */
        private GuardBinding $binding,

        /** Ends the identity's other sessions. */
        private SessionRevocations $revocations,

        /** Revokes the current session and reports it once committed. */
        private RevocationWriter $writer,

        /** Judges what the current session still falls short of, and returns it to pending. */
        private PendingTransitions $transitions,

        /** Container the configuration is resolved from. */
        private Container $container,
    ) {}

    /**
     * Revoke every session of the identity but `$current` after a factor was
     * removed, then judge `$current` again without it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $factor
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorRemoval
     *
     * @throws \InvalidArgumentException
     */
    public function remove(Identity $identity, string $factor, ?Session $current, CarbonImmutable $now): FactorRemoval
    {
        if (!FactorReference::isValid($factor)) {
            throw new \InvalidArgumentException(sprintf('A removed factor is named by its reference, of 1 to %d characters.', FactorReference::MAX_LENGTH));
        }

        $session = $this->current($identity, $current, 'a factor\'s removal');

        $this->assertStored($identity, 'A factor\'s removal');

        return SessionLookup::model()->getConnection()->transaction(function () use ($identity, $factor, $session, $now): FactorRemoval {

            if ($session === null) {
                return new FactorRemoval($this->revocations->revokeSessions($identity, RevocationReason::FACTOR_REMOVED, null, $this->forgetting($identity)));
            }

            /** @var \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession> $ended */
            $ended   = new \ArrayObject;
            $revoked = $this->revocations->revokeSessions($identity, RevocationReason::FACTOR_REMOVED, $session, $this->forgettingEach($ended));

            return $this->recheck($identity, $session, $factor, $revoked, $ended, $now);
        });
    }

    /**
     * Judge `$current` again after the factor package made the change from it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade  $change
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     *
     * @throws \InvalidArgumentException
     */
    public function change(Identity $identity, FactorChangeMade $change, Session $current, CarbonImmutable $now): FactorChangeResult
    {
        $session = $this->current($identity, $current, 'a factor\'s change');
        $reason  = $change === FactorChangeMade::FACTOR_REMOVED ? RevocationReason::FACTOR_REMOVED : RevocationReason::FACTOR_CHANGED;

        return SessionLookup::model()->getConnection()->transaction(function () use ($identity, $session, $reason, $now): FactorChangeResult {

            $locked = SessionLookup::lock($session->getSessionIdentifier());

            if (!SessionOwnership::isSameSession($session, $locked) || OwnedSession::refusal($locked, $this->context->name(), $now) !== null) {
                return FactorChangeResult::skipped();
            }

            IssuanceGuard::hold($locked);

            /** @var \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession> $ended */
            $ended = new \ArrayObject;

            $this->afterCommit()->run($locked, $this->forgettingEach($ended));

            return $this->judge($identity, $locked, $reason, $ended, $now);
        });
    }

    /**
     * Revoke every session of the identity after its further factors were
     * reset, returning how many this call revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function reset(Identity $identity): int
    {
        $this->assertStored($identity, 'A reset of factors');

        return $this->revocations->revokeSessions($identity, RevocationReason::FACTOR_RESET, null, $this->forgetting($identity));
    }

    /**
     * What forgets the guard's binding to the identity once the change commits.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \Closure(): void
     */
    private function forgetting(Identity $identity): \Closure
    {
        $binding = $this->binding;

        return static function () use ($binding, $identity): void {
            $binding->forgetIdentity($identity);
        };
    }

    /**
     * What forgets the guard's binding to any of the ended sessions once the
     * change commits.
     *
     * @param  \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $ended
     * @return \Closure(): void
     */
    private function forgettingEach(\ArrayObject $ended): \Closure
    {
        $binding = $this->binding;

        return static function () use ($binding, $ended): void {
            foreach ($ended as $session) {
                $binding->forgetSession($session);
            }
        };
    }

    /**
     * The current session given, once it is a session of this guard that the
     * identity owns.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @param  string  $flow
     * @return ($current is null ? null : \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)
     *
     * @throws \InvalidArgumentException
     */
    private function current(Identity $identity, ?Session $current, string $flow): (EloquentSession&Model)|null
    {
        if ($current === null) {
            return null;
        }

        $guard = $this->context->name();

        if (!$current instanceof EloquentSession || !$current instanceof Model || $current->getGuard() !== $guard || !SessionOwnership::isOwner($current, $identity)) {
            throw new \InvalidArgumentException(sprintf('The current session of %s must be a session of guard [%s] that the identity owns.', $flow, $guard));
        }

        return $current;
    }

    /**
     * Refuse an identity that does not live on the storage connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $flow
     * @return void
     *
     * @throws \LogicException
     */
    private function assertStored(Identity $identity, string $flow): void
    {
        $mismatch = $identity instanceof Model ? SharedConnection::mismatch($identity, $this->container->make(Repository::class)) : null;

        if ($mismatch !== null) {
            throw new \LogicException(sprintf('%s moves the identity\'s cutoff and ends its sessions in the factor package\'s transaction, so %s', $flow, $mismatch));
        }
    }

    /**
     * Lock the current session, void its proofs made with the factor and judge
     * it again when it is active.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $current
     * @param  string  $factor
     * @param  int  $revoked
     * @param  \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $ended
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorRemoval
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function recheck(Identity $identity, EloquentSession&Model $current, string $factor, int $revoked, \ArrayObject $ended, CarbonImmutable $now): FactorRemoval
    {
        $guard  = $this->context->name();
        $locked = SessionLookup::lock($current->getSessionIdentifier());

        if (!SessionOwnership::isSameSession($current, $locked)) {
            return new FactorRemoval($revoked);
        }

        $refusal = OwnedSession::refusal($locked, $guard, $now);
        $pending = $refusal === FailureReason::SESSION_PENDING && !SessionDeadlines::hasEnded($locked, $now);

        if ($refusal !== null && !$pending) {
            return new FactorRemoval($revoked);
        }

        IssuanceGuard::hold($locked);

        ProofWriter::void($locked, $guard, $factor, $now);
        ContextForgetting::now($locked);
        ContextForgetting::onSettle($this->afterCommit(), $locked);

        if ($pending) {
            return new FactorRemoval($revoked);
        }

        $result = $this->judge($identity, $locked, RevocationReason::FACTOR_REMOVED, $ended, $now);

        return new FactorRemoval($revoked + ($result->isRevoked() ? 1 : 0), $result->isRevoked(), $result->pending, $result->credential);
    }

    /**
     * Keep the locked session active, return it to pending or revoke it, as its
     * current proofs stand.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $ended
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function judge(Identity $identity, EloquentSession&Model $locked, RevocationReason $reason, \ArrayObject $ended, CarbonImmutable $now): FactorChangeResult
    {
        $verdict = $this->verdict($locked, $now);

        if ($verdict === null) {
            return $this->revoke($identity, $locked, $reason, $ended, $now);
        }

        [$admitted, $policy] = $verdict;

        $firstFactor = PendingTransitions::firstFactorOf($locked, $policy, current: true);
        $outstanding = $this->transitions->outstanding($locked, $admitted->identity, $policy->factor, $firstFactor, $now, current: true);

        if ($outstanding->isEmpty()) {
            return FactorChangeResult::active();
        }

        $returned = $this->transitions->returnToPending($locked, $admitted, $policy->version, $outstanding, $firstFactor, AuthenticationFlow::FACTOR_CHANGE, $now);

        return $returned === null ? $this->revoke($identity, $locked, $reason, $ended, $now) : $this->returned($locked, $returned, $ended);
    }

    /**
     * The locked session admitted as a refresh admits it, with its tenant
     * policy verdict, or `null` when it no longer stands.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?array{0: \SineMacula\Laravel\Authentication\Admission\Admitted, 1: \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function verdict(EloquentSession&Model $locked, CarbonImmutable $now): ?array
    {
        $guard    = $this->context->name();
        $hint     = $locked->getAttribute(PrincipalReference::columns($locked)[1]);
        $admitted = (new RefreshAdmission($guard, $this->context->provider(), $this->context->resolver()))->admit($locked, $hint);

        if (!$admitted instanceof Admitted || !PrincipalReference::isRecordedOn($locked, $admitted->principal)) {
            return null;
        }

        $policy = TenantPolicyCheck::check($guard, $admitted->identity, $admitted->principal, $admitted->tenant, $locked, $now, new ProofSource(current: true));

        return $policy->standing === TenantPolicyStanding::SSO_REQUIRED ? null : [$admitted, $policy];
    }

    /**
     * Revoke the locked session and add it to the sessions whose binding is
     * forgotten.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $ended
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     */
    private function revoke(Identity $identity, EloquentSession&Model $locked, RevocationReason $reason, \ArrayObject $ended, CarbonImmutable $now): FactorChangeResult
    {
        $context = new EventContext($locked->getGuard(), $this->context->client(), $identity, session: $locked, method: $locked->getSignInMethod(), fromSession: true);
        $event   = new SessionRevoked($context, $reason);
        $current = $this->writer->revoke($locked, $reason, $now, fn () => $this->context->dispatch($event));

        $ended->append($locked);

        return $current ? FactorChangeResult::revoked() : FactorChangeResult::skipped();
    }

    /**
     * The judgement's answer once the locked session returned to pending.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \SineMacula\Laravel\Authentication\Sessions\ReturnedToPending  $returned
     * @param  \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $ended
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     */
    private function returned(EloquentSession&Model $locked, ReturnedToPending $returned, \ArrayObject $ended): FactorChangeResult
    {
        $ended->append($locked);

        return FactorChangeResult::pending($returned->pending, $returned->credential);
    }

    /**
     * What defers work until the session model's connection commits.
     *
     * @return \SineMacula\Laravel\Authentication\Database\AfterCommit
     */
    private function afterCommit(): AfterCommit
    {
        $container = $this->container;

        return new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null);
    }
}
