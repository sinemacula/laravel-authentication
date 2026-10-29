<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * The writes and the locking re-read behind a refresh: each a single statement
 * on the device's own connection, guarded so that it only applies to the state
 * it was decided on.
 *
 * Writes go through the query builder, so Eloquent observers do not fire and
 * unsaved in-memory attributes never reach the row; each successful write is
 * then mirrored on the in-memory device as persisted state. Every timestamp is
 * formatted with the device model's own date format.
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

        /** Resolver for the device's own connection. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Rotate the device from the presented rotation id to the next one, and
     * move its idle deadline, in one compare-and-swap UPDATE.
     *
     * The swap applies only while the row still holds the presented id as its
     * current one, is not revoked, and has both deadlines exactly as they were
     * loaded: any concurrent rotation, revocation, or deadline change makes it
     * affect no row. It records the presented id as the previous one and `$now`
     * as the rotation time. Returns whether the row was rotated.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $presentedRotationId
     * @param  string  $nextRotationId
     * @param  \Carbon\CarbonImmutable  $idle
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @imperative
     */
    public function rotate(
        EloquentDevice&Model $device,
        #[\SensitiveParameter] string $presentedRotationId,
        #[\SensitiveParameter] string $nextRotationId,
        CarbonImmutable $idle,
        CarbonImmutable $now,
    ): bool {
        $presentedDigest = RefreshTokenHasher::hash($presentedRotationId);

        $rotated = [
            $device->getRefreshKeyName()         => RefreshTokenHasher::hash($nextRotationId),
            $device->getPreviousRefreshKeyName() => $presentedDigest,
            $device->getRefreshRotatedAtName()   => $device->fromDateTime($now),
            $device->getIdleExpiresAtName()      => $device->fromDateTime($idle),
        ];

        $affected = $this->table($device)
            ->where($device->getRefreshKeyName(), $presentedDigest)
            ->whereNull($device->getRevokedAtName())
            ->where($this->loadedDeadlines($device))
            ->update($rotated);

        return $this->mirror($device, $affected, $rotated);
    }

    /**
     * Revoke the device: record the time and reason and clear both refresh
     * digests, unless it is already revoked, in which case the first
     * revocation's time and reason are kept. Returns whether this call revoked
     * it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @imperative
     */
    public function revoke(EloquentDevice&Model $device, RevocationReason $reason, CarbonImmutable $now): bool
    {
        $revoked = [
            $device->getRevokedAtName()          => $device->fromDateTime($now),
            $device->getRevokedReasonName()      => $reason->value,
            $device->getRefreshKeyName()         => null,
            $device->getPreviousRefreshKeyName() => null,
        ];

        $affected = $this->table($device)
            ->whereNull($device->getRevokedAtName())
            ->update($revoked);

        return $this->mirror($device, $affected, $revoked);
    }

    /**
     * Read the device again from the write connection with a locking read, so a
     * refresh that lost its compare-and-swap judges the row as it now is.
     * Inside a caller's transaction the lock is held until it ends; outside
     * one, the locking read still returns the latest committed row. Returns
     * `null` when the device no longer exists.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     */
    public function reload(EloquentDevice&Model $device): (EloquentDevice&Model)|null
    {
        $fresh = WriteConnection::during($device, static fn (): mixed => WriteConnection::query($device->newQuery())->lockForUpdate()->find($device->getKey()));

        return $fresh instanceof $device ? $fresh : null;
    }

    /**
     * Start a query on the device's row, on the device's own connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return \Illuminate\Database\Query\Builder
     */
    private function table(EloquentDevice&Model $device): Builder
    {
        return $this->connections
            ->connection($device->getConnectionName())
            ->table($device->getTable())
            ->where($device->getKeyName(), $device->getKey());
    }

    /**
     * The device's idle and absolute deadlines exactly as they were loaded,
     * keyed by column, for a swap that must match them by equality.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return array<string, mixed>
     */
    private function loadedDeadlines(EloquentDevice&Model $device): array
    {
        $idle     = $device->getIdleExpiresAtName();
        $absolute = $device->getAbsoluteExpiresAtName();

        return [
            $idle     => $device->getRawOriginal($idle),
            $absolute => $device->getRawOriginal($absolute),
        ];
    }

    /**
     * Mirror a write on the in-memory device as persisted state when it changed
     * the row, and report whether it did.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  int  $affected
     * @param  array<string, mixed>  $values
     * @return bool
     *
     * @imperative
     */
    private function mirror(EloquentDevice&Model $device, int $affected, array $values): bool
    {
        if ($affected !== 1) {
            return false;
        }

        $device->forceFill($values)->syncOriginalAttributes(array_keys($values));

        return true;
    }
}
