<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\SessionRecords\SwitchFloor;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * The guarded writes and the locking re-read behind a refresh, each a single
 * statement on the session's own connection.
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
            ->where(self::loaded($session, [$session->getIdleExpiresAtName(), $session->getAbsoluteExpiresAtName()]))
            ->where($version, $loaded)
            ->update($rotated);

        return $this->mirror($session, $affected, $rotated);
    }

    /**
     * Rotate the session to the next rotation id for a switch, moving both
     * deadlines and recording the destination, in one compare-and-swap UPDATE.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  array{0: string, 1: string}  $rotation
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  ?string  $policyVersion
     * @param  array{0: \Carbon\CarbonImmutable, 1: ?\Carbon\CarbonImmutable}  $deadlines
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public function switchSession(
        EloquentSession&Model $session,
        #[\SensitiveParameter] array $rotation,
        Admitted $destination,
        ?string $policyVersion,
        array $deadlines,
        CarbonImmutable $now,
    ): bool {
        [$type, $id]       = PrincipalReference::columns($session);
        [$idle, $absolute] = $deadlines;
        $presentedDigest   = RefreshTokenHasher::hash($rotation[0]);

        $switched = [
            $session->getRefreshKeyName()          => RefreshTokenHasher::hash($rotation[1]),
            $session->getPreviousRefreshKeyName()  => $presentedDigest,
            $session->getRefreshRotatedAtName()    => $session->fromDateTime($now),
            $session->getIdleExpiresAtName()       => $session->fromDateTime($idle),
            $session->getAbsoluteExpiresAtName()   => $session->fromDateTime($absolute),
            $session->getTenantPolicyVersionName() => $policyVersion,
        ];

        if (in_array(true, self::contextChanges($session, $destination), true)) {
            $switched += [
                $type                         => PrincipalReference::type($destination->principal),
                $id                           => PrincipalReference::id($destination->principal),
                $session->getTenantIdName()   => IdentifierCoercion::stringify($destination->tenant?->getTenantIdentifier()),
                $session->getSwitchedAtName() => $session->fromDateTime(SwitchFloor::after($session->getSwitchedAt(), $now)),
            ];
        }

        $affected = $this->table($session)
            ->where($session->getStatusName(), SessionStatus::ACTIVE->value)
            ->where($session->getRefreshKeyName(), $presentedDigest)
            ->whereNull($session->getRevokedAtName())
            ->where(self::loaded($session, [$session->getIdleExpiresAtName(), $session->getAbsoluteExpiresAtName()]))
            ->where(self::loaded($session, [$type, $id, $session->getTenantIdName(), $session->getTenantPolicyVersionName()]))
            ->update($switched);

        return $this->mirror($session, $affected, $switched);
    }

    /**
     * Whether the destination's principal, and its active tenant, differ from
     * the ones the session recorded as it was loaded.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @return array{0: bool, 1: bool}
     */
    public static function contextChanges(EloquentSession&Model $session, Admitted $destination): array
    {
        [$type, $id] = PrincipalReference::columns($session);

        $principal = $session->getRawOriginal($type) !== PrincipalReference::type($destination->principal)
            || !IdentifierCoercion::matches($session->getRawOriginal($id), PrincipalReference::id($destination->principal));
        $tenant = IdentifierCoercion::stringify($session->getRawOriginal($session->getTenantIdName()))
            !== IdentifierCoercion::stringify($destination->tenant?->getTenantIdentifier());

        return [$principal, $tenant];
    }

    /**
     * Revoke the session unless it is already revoked, and report whether this
     * call revoked it.
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
     * Revoke the active session only while it is still as it was loaded, and
     * report whether this call revoked it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @imperative
     */
    public function revokeAsLoaded(EloquentSession&Model $session, RevocationReason $reason, CarbonImmutable $now): bool
    {
        [$type, $id] = PrincipalReference::columns($session);

        $revoked = self::revocation($session, $reason, $now);

        $affected = $this->table($session)
            ->where($session->getStatusName(), SessionStatus::ACTIVE->value)
            ->whereNull($session->getRevokedAtName())
            ->where(self::loaded($session, [$session->getRefreshKeyName(), $type, $id, $session->getTenantIdName()]))
            ->update($revoked);

        return $this->mirror($session, $affected, $revoked);
    }

    /**
     * The columns a revocation writes, keyed by column.
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
     * Read the session again from the write connection with a locking read, or
     * `null` when it no longer exists.
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
     * The columns exactly as they were loaded, keyed by column, for a swap that
     * must match them by equality: a `null` one is matched as `IS NULL`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  list<string>  $columns
     * @return array<string, mixed>
     */
    private static function loaded(EloquentSession&Model $session, array $columns): array
    {
        $loaded = [];

        foreach ($columns as $column) {
            $loaded[$column] = $session->getRawOriginal($column);
        }

        return $loaded;
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
