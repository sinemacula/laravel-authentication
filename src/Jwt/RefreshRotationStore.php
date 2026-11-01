<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * The writes and the locking re-read behind a refresh: each a single statement
 * on the session's own connection, guarded so that it only applies to the state
 * it was decided on.
 *
 * Writes go through the query builder, so Eloquent observers do not fire and
 * unsaved in-memory attributes never reach the row; each successful write is
 * then mirrored on the in-memory session as persisted state. Every timestamp is
 * formatted with the session model's own date format.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshRotationStore
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     */
    public function __construct(

        /** Resolver for the session's own connection. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Rotate the session from the presented rotation id to the next one, and
     * move its idle deadline, in one compare-and-swap UPDATE.
     *
     * The swap applies only while the row still holds the presented id as its
     * current one, is active and not revoked, and has both deadlines exactly as
     * they were loaded (a `null` absolute one matched as `IS NULL`): any
     * concurrent rotation, revocation, return to pending, or deadline change
     * makes it affect no row. Its status is matched as well as its deadlines,
     * since a pending session's deadline can equal the one it held while
     * active. It records the presented id as the previous one and `$now` as the
     * rotation time. The tenant authentication policy version the refresh was
     * checked against is matched as loaded, so a version the policy-change
     * helper wrote meanwhile makes the swap miss and the refresh be judged
     * again, and written when it differs. Returns whether the row was rotated.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $presentedRotationId
     * @param  string  $nextRotationId
     * @param  \Carbon\CarbonImmutable  $idle
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?string  $policyVersion
     * @return bool
     *
     * @imperative
     */
    public function rotate(
        EloquentSession&Model $session,
        #[\SensitiveParameter] string $presentedRotationId,
        #[\SensitiveParameter] string $nextRotationId,
        CarbonImmutable $idle,
        CarbonImmutable $now,
        ?string $policyVersion = null,
    ): bool {
        $presentedDigest = RefreshTokenHasher::hash($presentedRotationId);

        $rotated = [
            $session->getRefreshKeyName()         => RefreshTokenHasher::hash($nextRotationId),
            $session->getPreviousRefreshKeyName() => $presentedDigest,
            $session->getRefreshRotatedAtName()   => $session->fromDateTime($now),
            $session->getIdleExpiresAtName()      => $session->fromDateTime($idle),
        ];

        $version = $session->getTenantPolicyVersionName();
        $loaded  = $session->getRawOriginal($version);

        if ($loaded !== $policyVersion) {
            $rotated[$version] = $policyVersion;
        }

        $affected = $this->table($session)
            ->where($session->getRefreshKeyName(), $presentedDigest)
            ->where($session->getStatusName(), SessionStatus::ACTIVE->value)
            ->whereNull($session->getRevokedAtName())
            ->where($this->loadedDeadlines($session))
            ->where($version, $loaded)
            ->update($rotated);

        return $this->mirror($session, $affected, $rotated);
    }

    /**
     * Rotate the session from the presented rotation id to the next one for a
     * switch of principal, and move both deadlines (the absolute one only ever
     * lowered, or kept `null`), in one compare-and-swap UPDATE; when
     * `$switching`, also record the target as the principal the session acts
     * as, its tenant as the session's active tenant, and `$now` as the time of
     * the switch.
     *
     * The swap applies only while the row still holds the presented id as its
     * current one, is not revoked, has both deadlines and records the principal
     * exactly as they were loaded: any concurrent rotation, switch, revocation
     * or deadline change makes it affect no row. Returns whether the row was
     * switched.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $presentedRotationId
     * @param  string  $nextRotationId
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $target
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  bool  $switching
     * @param  array{0: \Carbon\CarbonImmutable, 1: ?\Carbon\CarbonImmutable}  $deadlines
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @imperative
     */
    public function switchPrincipal(
        EloquentSession&Model $session,
        #[\SensitiveParameter] string $presentedRotationId,
        #[\SensitiveParameter] string $nextRotationId,
        Principal $target,
        ?Tenant $tenant,
        bool $switching,
        array $deadlines,
        CarbonImmutable $now,
    ): bool {
        [$type, $id]       = PrincipalReference::columns($session);
        [$idle, $absolute] = $deadlines;
        $presentedDigest   = RefreshTokenHasher::hash($presentedRotationId);

        $switched = [
            $session->getRefreshKeyName()         => RefreshTokenHasher::hash($nextRotationId),
            $session->getPreviousRefreshKeyName() => $presentedDigest,
            $session->getRefreshRotatedAtName()   => $session->fromDateTime($now),
            $session->getIdleExpiresAtName()      => $session->fromDateTime($idle),
            $session->getAbsoluteExpiresAtName()  => $session->fromDateTime($absolute),
        ];

        if ($switching) {
            $switched += [
                $type                         => PrincipalReference::type($target),
                $id                           => PrincipalReference::id($target),
                $session->getTenantIdName()   => IdentifierCoercion::stringify($tenant?->getTenantIdentifier()),
                $session->getSwitchedAtName() => $session->fromDateTime($now),
            ];
        }

        $affected = $this->table($session)
            ->where($session->getRefreshKeyName(), $presentedDigest)
            ->whereNull($session->getRevokedAtName())
            ->where($this->loadedDeadlines($session))
            ->where([$type => $session->getRawOriginal($type), $id => $session->getRawOriginal($id)])
            ->update($switched);

        return $this->mirror($session, $affected, $switched);
    }

    /**
     * Revoke the session: record the time and reason and clear both refresh
     * digests, unless it is already revoked, in which case the first
     * revocation's time and reason are kept. Returns whether this call revoked
     * it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @imperative
     */
    public function revoke(EloquentSession&Model $session, RevocationReason $reason, CarbonImmutable $now): bool
    {
        $revoked = self::revocation($session, $reason, $now);

        $affected = $this->table($session)
            ->whereNull($session->getRevokedAtName())
            ->update($revoked);

        return $this->mirror($session, $affected, $revoked);
    }

    /**
     * The columns a revocation writes, keyed by column: the time and reason,
     * and both refresh digests cleared, so no refresh token of the session is
     * accepted again.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return array<string, mixed>
     */
    public static function revocation(EloquentSession&Model $session, RevocationReason $reason, CarbonImmutable $now): array
    {
        return [
            $session->getRevokedAtName()          => $session->fromDateTime($now),
            $session->getRevokedReasonName()      => $reason->value,
            $session->getRefreshKeyName()         => null,
            $session->getPreviousRefreshKeyName() => null,
        ];
    }

    /**
     * Read the session again from the write connection with a locking read, so
     * a refresh that lost its compare-and-swap judges the row as it now is.
     * Inside a caller's transaction the lock is held until it ends; outside
     * one, the locking read still returns the latest committed row. Returns
     * `null` when the session no longer exists.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     */
    public function reload(EloquentSession&Model $session): (EloquentSession&Model)|null
    {
        $fresh = WriteConnection::during($session, static fn (): mixed => WriteConnection::query($session->newQuery())->lockForUpdate()->find($session->getKey()));

        return $fresh instanceof $session ? $fresh : null;
    }

    /**
     * Start a query on the session's row, on the session's own connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Query\Builder
     */
    private function table(EloquentSession&Model $session): Builder
    {
        return $this->connections
            ->connection($session->getConnectionName())
            ->table($session->getTable())
            ->where($session->getKeyName(), $session->getKey());
    }

    /**
     * The session's idle and absolute deadlines exactly as they were loaded,
     * keyed by column, for a swap that must match them by equality: a `null`
     * one is matched as `IS NULL`, which the query builder writes for a `null`
     * value.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return array<string, mixed>
     */
    private function loadedDeadlines(EloquentSession&Model $session): array
    {
        $idle     = $session->getIdleExpiresAtName();
        $absolute = $session->getAbsoluteExpiresAtName();

        return [
            $idle     => $session->getRawOriginal($idle),
            $absolute => $session->getRawOriginal($absolute),
        ];
    }

    /**
     * Mirror a write on the in-memory session as persisted state when it
     * changed the row, and report whether it did.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  int  $affected
     * @param  array<string, mixed>  $values
     * @return bool
     *
     * @imperative
     */
    private function mirror(EloquentSession&Model $session, int $affected, array $values): bool
    {
        if ($affected !== 1) {
            return false;
        }

        $session->forceFill($values)->syncOriginalAttributes(array_keys($values));

        return true;
    }
}
