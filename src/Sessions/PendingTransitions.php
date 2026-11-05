<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SwitchFloor;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;

/**
 * Returns an active session that fell short of a further factor during a
 * request (a refresh, a switch, the removal of a factor it was proved with, or
 * another change of the identity's factors) to pending, instead of re-issuing
 * its pair.
 *
 * One compare-and-swap on the row, as the caller loaded it, makes it pending:
 * it waits on a further factor, holds the digest of a new pending credential,
 * idles out when that credential expires (never past its absolute deadline),
 * records the destination the caller admitted (its principal and active tenant)
 * and the version of the destination's policy the caller judged it against, and
 * moves the floor for its access tokens' issue time (`SwitchFloor`). Its
 * refresh digests are kept: a refresh or switch of a pending session is refused
 * as `session_pending` before any digest is compared, so its old refresh token
 * is never taken for a replay, and its activation replaces them. From the
 * commit, every one of its access and refresh tokens is refused.
 * `SessionReturnedToPending` reports it once committed on the session's
 * connection.
 *
 * A requirement the session cannot meet in place (sign-in through a tenant's
 * own connections) is never a reason to return to pending: the caller refuses
 * it instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingTransitions
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     */
    public function __construct(

        /** The context of the guard whose sessions return to pending. */
        private GuardContext $context,

        /** Defers the report until the return commits. */
        private AfterCommit $afterCommit,

        /** Configuration the pending credential's lifetime is read from. */
        private Repository $config,

        /** The client a return is reported with, or `null` for the guard's request's. */
        private ?ClientContext $client = null,
    ) {}

    /**
     * The first factor the session signed in with, as its tenant's verdict was
     * judged on it, or, when the verdict asked for no further factor, as the
     * session records it, so a caller judging the session again, or returning
     * it to pending, reads it at most once, current when asked. Pass `$current`
     * only for a session whose row this transaction holds locked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict  $verdict
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function firstFactorOf(Session $session, TenantPolicyVerdict $verdict, bool $current = false): RecordedProof
    {
        return $verdict->firstFactor ?? PendingEvaluation::firstFactorOf($session, $current);
    }

    /**
     * What an active session's authentication falls short of: the strictest of
     * its tenant's requirement (empty when the tenant asks for none) and the
     * identity-level one while the session still owes it, judged on the
     * session's recorded origin, client name, platform and the first factor
     * given (see `PendingEvaluation::owedFactorOn()`), so a session returned to
     * pending names everything its next action is judged against. Empty when
     * nothing is outstanding. Its proofs are read current when asked: pass
     * `$current` only for a session whose row this transaction holds locked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $tenant
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function outstanding(
        EloquentSession&Model $session,
        Identity $identity,
        Requirement $tenant,
        RecordedProof $firstFactor,
        CarbonImmutable $now,
        bool $current = false,
    ): Requirement {
        $owed = (new PendingEvaluation($this->context, Container::getInstance()))->owedFactorOn($session, $identity, $firstFactor, null, $now, $current);

        return Requirement::strictest($owed, $tenant);
    }

    /**
     * Return the active session to pending instead of re-issuing its pair,
     * recording the destination the caller admitted (its principal and active
     * tenant) and the version of the destination's policy the caller judged it
     * against, which the destination's policy-change helper compares with its
     * own, and answering the pending session with the requirement the caller
     * found it falls short of: one compare-and-swap on the row as the caller
     * loaded it, while it is active and unrevoked with the refresh digest,
     * principal, active tenant, policy version and both deadlines it was loaded
     * with. Returns `null` when the row changed since it was loaded, so the
     * caller judges it again, as after a lost rotation.
     * `SessionReturnedToPending`, scheduled for the commit, carries the client
     * this was built with, or, without one, the guard's request's.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  ?string  $policyVersion
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    public function returnToPending(
        EloquentSession&Model $session,
        Admitted $destination,
        ?string $policyVersion,
        Requirement $requirement,
        RecordedProof $firstFactor,
        AuthenticationFlow $flow,
        CarbonImmutable $now,
    ): ?ReturnedToPending {
        [$type, $id] = PrincipalReference::columns($session);

        $secret   = RefreshTokenHasher::generate();
        $expiry   = PendingState::expiry($now, PendingState::ttlSeconds($this->config), $session->getAbsoluteExpiresAt());
        $tenantId = IdentifierCoercion::stringify($destination->tenant?->getTenantIdentifier());
        $loaded   = self::loaded($session, $type, $id);

        $values = [
            $session->getStatusName()              => SessionStatus::PENDING->value,
            $session->getRequiresName()            => PendingState::requires([PendingRequirement::MFA]),
            $session->getPendingKeyName()          => RefreshTokenHasher::hash($secret),
            $session->getIdleExpiresAtName()       => $session->fromDateTime($expiry),
            $session->getSwitchedAtName()          => $session->fromDateTime(SwitchFloor::after($session->getSwitchedAt(), $now)),
            $type                                  => PrincipalReference::type($destination->principal),
            $id                                    => PrincipalReference::id($destination->principal),
            $session->getTenantIdName()            => $tenantId,
            $session->getTenantPolicyVersionName() => $policyVersion,
        ];

        $affected = $session->getConnection()
            ->table($session->getTable())
            ->where($session->getKeyName(), $session->getKey())
            ->where($session->getStatusName(), SessionStatus::ACTIVE->value)
            ->whereNull($session->getRevokedAtName())
            ->where($loaded)
            ->update($values);

        if ($affected !== 1) {
            return null;
        }

        PendingState::mirror($session, $values);

        $pending = new PendingSession(
            $session->getSessionIdentifier(),
            $this->context->name(),
            $destination->identity,
            $destination->principal,
            $destination->tenant,
            [PendingRequirement::MFA],
            (string) $session->getSignInMethod(),
            $expiry,
            $session,
            $requirement,
            $firstFactor,
        );

        $this->report($session, $pending, $flow, $loaded, $values);

        return new ReturnedToPending($pending, new Secret(IdentifierCoercion::stringify($session->getSessionIdentifier()) . '.' . $secret));
    }

    /**
     * The raw values the compare-and-swap requires unchanged since the caller
     * loaded the session: its refresh digest, principal, active tenant, policy
     * version and both deadlines.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $type
     * @param  string  $id
     * @return array<string, mixed>
     */
    private static function loaded(EloquentSession&Model $session, string $type, string $id): array
    {
        $columns = [
            $session->getRefreshKeyName(),
            $type,
            $id,
            $session->getTenantIdName(),
            $session->getTenantPolicyVersionName(),
            $session->getIdleExpiresAtName(),
            $session->getAbsoluteExpiresAtName(),
        ];

        $loaded = [];

        foreach ($columns as $column) {
            $loaded[$column] = $session->getRawOriginal($column);
        }

        return $loaded;
    }

    /**
     * Schedule `SessionReturnedToPending` for the return's commit, naming the
     * principal and tenant the session left when the destination changed them.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  array<string, mixed>  $loaded
     * @param  array<string, mixed>  $values
     * @return void
     */
    private function report(EloquentSession&Model $session, PendingSession $pending, AuthenticationFlow $flow, array $loaded, array $values): void
    {
        [$type, $id] = PrincipalReference::columns($session);
        $tenant      = $session->getTenantIdName();

        $changed = $loaded[$type]   !== $values[$type] || $loaded[$id] !== $values[$id];
        $moved   = $loaded[$tenant] !== $values[$tenant];
        $client  = $this->client ?? $this->context->client();

        $event = new SessionReturnedToPending(
            new EventContext($this->context->name(), $client, $pending->identity, $pending->principal, $pending->tenant, $session, $pending->method),
            [PendingRequirement::MFA->value],
            $pending->expiresAt,
            $flow,
            $changed ? IdentifierCoercion::stringify($loaded[$type]) : null,
            $changed ? IdentifierCoercion::stringify($loaded[$id]) : null,
            $moved ? IdentifierCoercion::stringify($loaded[$tenant]) : null,
        );

        $this->afterCommit->run($session, fn () => $this->context->dispatch($event));
    }
}
