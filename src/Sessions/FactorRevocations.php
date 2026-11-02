<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Factors\FactorReference;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;

/**
 * Ends sessions when the factor package removes one of an identity's factors or
 * resets them all: the two mandatory triggers, which the factor package calls
 * synchronously inside its own change and no setting turns off.
 *
 * A removal revokes every session of the identity but the current one, as
 * `factor_removed`, then judges the current one again without the factor: the
 * proofs it made with that factor are voided, and an active one stays active
 * while it still meets what the identity's factor policy and its tenant's
 * policy ask of it, returns to pending while it falls short of a further factor
 * only, and is revoked when nothing it could do in place would meet them; a
 * pending one stays pending, its next action judged without those proofs; with
 * no current session, every session is revoked, and the guard's binding to the
 * identity is forgotten. A reset revokes every session of the identity, the
 * current one included, as `factor_reset`, and forgets the guard's binding to
 * the identity. Either needs the identity on the storage connection, so its
 * cutoff moves and its sessions end in the factor package's transaction, and
 * runs on the session model's connection in one transaction, a savepoint inside
 * the caller's. Once that commits, the guard first forgets its binding, so the
 * rest of the request is not authenticated as a session it ended even when a
 * listener throws, and then its events are reported.
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
     * The factor `$factor` (the factor package's reference to it, 1 to 255
     * characters) was removed: revoke every session of the identity but
     * `$current`, then judge `$current` again without the factor. `$current`,
     * when given, must be a session of this guard owned by the identity; it is
     * left as it is when it has meanwhile been revoked or ended, and a pending
     * one has its proofs made with the factor voided and stays pending. When
     * the guard is bound to it and it is returned to pending or revoked, the
     * binding is forgotten once the removal commits; with no `$current`, every
     * session of the identity is revoked, and the guard's binding to the
     * identity is forgotten then, as a reset forgets it.
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

        $session = $this->current($identity, $current);

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
     * The identity's further factors were reset: revoke every session of the
     * identity, the current one included (`factor_reset`), and, when the guard
     * is bound to the identity, forget the binding once the reset commits.
     * Returns how many sessions this call revoked.
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
     * What forgets the guard's binding to the identity once the change that
     * revoked every session of it commits, so the rest of the request is not
     * authenticated as a session it ended; a rollback keeps the binding.
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
     * What forgets the guard's binding to whichever of the sessions it is bound
     * to, once the removal commits: the current session joins them when the
     * removal returns it to pending or revokes it.
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
     * identity owns, or `null` when none was given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \InvalidArgumentException
     */
    private function current(Identity $identity, ?Session $current): (EloquentSession&Model)|null
    {
        if ($current === null) {
            return null;
        }

        $guard = $this->context->name();

        if (!$current instanceof EloquentSession || !$current instanceof Model || $current->getGuard() !== $guard || !SessionOwnership::isOwner($current, $identity)) {
            throw new \InvalidArgumentException(sprintf('The current session of a factor\'s removal must be a session of guard [%s] that the identity owns.', $guard));
        }

        return $current;
    }

    /**
     * Refuse an identity that does not live on the storage connection, naming
     * the flow and both connections.
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
     * Lock the current session and, while it is still the session given and
     * live, void its proofs made with the factor. An active one is then judged
     * again; a pending one stays pending, its next action judged without them.
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

        ProofWriter::void($locked, $guard, $factor, $now);

        return $pending ? new FactorRemoval($revoked) : $this->judge($identity, $locked, $revoked, $ended, $now);
    }

    /**
     * Judge the locked session without the factor: it stays active while
     * nothing is outstanding, returns to pending, recording the version of its
     * tenant's policy answered, while a further factor is (the strictest of the
     * identity-level requirement it still owes and its tenant's), and is
     * revoked when it is no longer admitted as a refresh admits it or its
     * tenant now requires a connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
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
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function judge(Identity $identity, EloquentSession&Model $locked, int $revoked, \ArrayObject $ended, CarbonImmutable $now): FactorRemoval
    {
        $verdict = $this->verdict($locked, $now);

        if ($verdict === null) {
            return $this->revoke($identity, $locked, $revoked, $ended, $now);
        }

        [$admitted, $policy] = $verdict;

        $firstFactor = PendingTransitions::firstFactorOf($locked, $policy);
        $outstanding = $this->transitions->outstanding($locked, $admitted->identity, $policy->factor, $firstFactor, $now);

        if ($outstanding->isEmpty()) {
            return new FactorRemoval($revoked);
        }

        $returned = $this->transitions->returnToPending($locked, $admitted, $policy->version, $outstanding, $firstFactor, AuthenticationFlow::FACTOR_CHANGE, $now);

        return $returned === null ? $this->revoke($identity, $locked, $revoked, $ended, $now) : $this->returned($locked, $returned, $revoked, $ended);
    }

    /**
     * The locked session admitted as a refresh admits it, as the principal it
     * records, with how it stands against its tenant's policy, or `null` when
     * it is not admitted or its tenant now requires a connection.
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

        $policy = TenantPolicyCheck::check($guard, $admitted->identity, $admitted->principal, $admitted->tenant, $locked, $now);

        return $policy->standing === TenantPolicyStanding::SSO_REQUIRED ? null : [$admitted, $policy];
    }

    /**
     * Revoke the locked session (`factor_removed`), report it once committed,
     * and add it to the sessions whose binding is forgotten then.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  int  $revoked
     * @param  \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $ended
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorRemoval
     */
    private function revoke(Identity $identity, EloquentSession&Model $locked, int $revoked, \ArrayObject $ended, CarbonImmutable $now): FactorRemoval
    {
        $reason  = RevocationReason::FACTOR_REMOVED;
        $context = new EventContext($locked->getGuard(), $this->context->client(), $identity, session: $locked, method: $locked->getSignInMethod(), fromSession: true);
        $event   = new SessionRevoked($context, $reason);
        $current = $this->writer->revoke($locked, $reason, $now, fn () => $this->context->dispatch($event));

        $ended->append($locked);

        return new FactorRemoval($revoked + ($current ? 1 : 0), $current);
    }

    /**
     * The removal's answer once the locked session returned to pending, added
     * to the sessions whose binding is forgotten once that commits.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \SineMacula\Laravel\Authentication\Sessions\ReturnedToPending  $returned
     * @param  int  $revoked
     * @param  \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $ended
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorRemoval
     */
    private function returned(EloquentSession&Model $locked, ReturnedToPending $returned, int $revoked, \ArrayObject $ended): FactorRemoval
    {
        $ended->append($locked);

        return new FactorRemoval($revoked, false, $returned->pending, $returned->credential);
    }
}
