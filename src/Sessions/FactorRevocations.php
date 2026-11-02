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
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
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
 * proofs it made with that factor are voided, and it stays active while it
 * still meets what the identity's factor policy and its tenant's policy ask of
 * it, returns to pending while it falls short of a further factor only, and is
 * revoked when nothing it could do in place would meet them. A reset revokes
 * every session of the identity, the current one included, as `factor_reset`.
 * Either needs the identity on the storage connection, so its cutoff moves and
 * its sessions end in the factor package's transaction, and runs on the session
 * model's connection in one transaction, a savepoint inside the caller's, its
 * events reported once that commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorRevocations
{
    /** @var int Longest factor reference, in characters. */
    private const int FACTOR_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionRevocations  $revocations
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation  $evaluation
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingTransitions  $transitions
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
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

        /** Asks what the identity's factor policy still asks of the current session. */
        private PendingEvaluation $evaluation,

        /** Returns the current session to pending. */
        private PendingTransitions $transitions,

        /** Defers forgetting the binding until the removal commits. */
        private AfterCommit $afterCommit,

        /** Container the configuration is resolved from. */
        private Container $container,
    ) {}

    /**
     * The factor `$factor` (the factor package's reference to it, 1 to 255
     * characters) was removed: revoke every session of the identity but
     * `$current`, then judge `$current` again without the factor. `$current`,
     * when given, must be a session of this guard owned by the identity; it is
     * left as it is when it has meanwhile been revoked, ended or returned to
     * pending. When the guard is bound to it and it is returned to pending or
     * revoked, the binding is forgotten once the removal commits.
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
        if ($factor === '' || mb_strlen($factor) > self::FACTOR_MAX_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A removed factor is named by its reference, of 1 to %d characters.', self::FACTOR_MAX_LENGTH));
        }

        $session = $this->current($identity, $current);

        $this->assertStored($identity, 'A factor\'s removal');

        return SessionLookup::model()->getConnection()->transaction(function () use ($identity, $factor, $session, $now): FactorRemoval {

            $revoked = $this->revocations->revokeSessions($identity, RevocationReason::FACTOR_REMOVED, $session);

            return $session === null ? new FactorRemoval($revoked) : $this->recheck($identity, $session, $factor, $revoked, $now);
        });
    }

    /**
     * The identity's further factors were reset: revoke every session of the
     * identity, the current one included (`factor_reset`). Returns how many
     * sessions this call revoked.
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

        return $this->revocations->revokeSessions($identity, RevocationReason::FACTOR_RESET);
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
     * Lock the current session and, while it is still the session given, live
     * and active, void its proofs made with the factor and judge it again.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $current
     * @param  string  $factor
     * @param  int  $revoked
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
    private function recheck(Identity $identity, EloquentSession&Model $current, string $factor, int $revoked, CarbonImmutable $now): FactorRemoval
    {
        $guard  = $this->context->name();
        $locked = SessionLookup::lock($current->getSessionIdentifier());

        if (!SessionOwnership::isSameSession($current, $locked) || OwnedSession::refusal($locked, $guard, $now) !== null) {
            return new FactorRemoval($revoked);
        }

        ProofWriter::void($locked, $guard, $factor, $now);

        return $this->judge($identity, $locked, $revoked, $now);
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
    private function judge(Identity $identity, EloquentSession&Model $locked, int $revoked, CarbonImmutable $now): FactorRemoval
    {
        $verdict = $this->verdict($locked, $now);

        if ($verdict === null) {
            return $this->revoke($identity, $locked, $revoked, $now);
        }

        [$admitted, $policy] = $verdict;

        $owed        = $this->evaluation->owedFactorOn($locked, $admitted->identity, PendingEvaluation::firstFactorOf($locked), null, $now);
        $outstanding = Requirement::strictest($owed, $policy->factor);

        if ($outstanding->isEmpty()) {
            return new FactorRemoval($revoked);
        }

        $returned = $this->transitions->returnToPending($locked, $admitted, $policy->version, $outstanding, AuthenticationFlow::FACTOR_CHANGE, $now);

        return $returned === null ? $this->revoke($identity, $locked, $revoked, $now) : $this->returned($locked, $returned, $revoked);
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
     * and forget the binding to it then.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  int  $revoked
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorRemoval
     */
    private function revoke(Identity $identity, EloquentSession&Model $locked, int $revoked, CarbonImmutable $now): FactorRemoval
    {
        $reason  = RevocationReason::FACTOR_REMOVED;
        $context = new EventContext($locked->getGuard(), $this->context->client(), $identity, session: $locked, method: $locked->getSignInMethod(), fromSession: true);
        $event   = new SessionRevoked($context, $reason);
        $current = $this->writer->revoke($locked, $reason, $now, fn () => $this->context->dispatch($event));

        $this->forget($locked);

        return new FactorRemoval($revoked + ($current ? 1 : 0), $current);
    }

    /**
     * The removal's answer once the locked session returned to pending, the
     * binding to it forgotten once that commits.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \SineMacula\Laravel\Authentication\Sessions\ReturnedToPending  $returned
     * @param  int  $revoked
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorRemoval
     */
    private function returned(EloquentSession&Model $locked, ReturnedToPending $returned, int $revoked): FactorRemoval
    {
        $this->forget($locked);

        return new FactorRemoval($revoked, false, $returned->pending, $returned->credential);
    }

    /**
     * Forget the guard's binding to the session, when it is bound to it, once
     * the removal commits.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     */
    private function forget(EloquentSession&Model $session): void
    {
        $binding = $this->binding;

        $this->afterCommit->run($session, static function () use ($binding, $session): void {
            $binding->forgetSession($session);
        });
    }
}
