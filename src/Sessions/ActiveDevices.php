<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Pagination\LengthAwarePaginator;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Which devices hold a live session, and the listing of an identity's live
 * devices.
 *
 * A device is active while it is not revoked and both its idle and absolute
 * deadlines are still ahead: a deadline has passed from the second it names, as
 * on every other path. The listing reads the identity's `devices()` relation on
 * the write connection, so it never shows a device a replica has not yet seen
 * revoked, and summarises each device without its digests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActiveDevices
{
    /** @var int Largest page the listing returns. */
    public const int MAX_PER_PAGE = 100;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Constrain a query of the device's model to the devices active at the
     * given time, with the columns its name accessors give.
     *
     * @param  \Illuminate\Contracts\Database\Eloquent\Builder  $query
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \Carbon\CarbonInterface  $now
     * @return void
     */
    public static function constrain(Builder $query, EloquentDevice&Model $device, CarbonInterface $now): void
    {
        $at = $device->fromDateTime($now);

        $query->whereNull($device->qualifyColumn($device->getRevokedAtName()))
            ->where($device->qualifyColumn($device->getIdleExpiresAtName()), '>', $at)
            ->where($device->qualifyColumn($device->getAbsoluteExpiresAtName()), '>', $at);
    }

    /**
     * One page of the identity's active devices, of every guard, most recently
     * used first (never used last), then by key, newest first, each summarised
     * and marked when it is the current device.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $current
     * @param  int  $perPage
     * @param  ?int  $page
     * @return \Illuminate\Pagination\LengthAwarePaginator<int, \SineMacula\Laravel\Authentication\Sessions\DeviceSummary>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function page(Identity $identity, ?Device $current, int $perPage, ?int $page): LengthAwarePaginator
    {
        if ($perPage < 1 || $perPage > self::MAX_PER_PAGE) {
            throw new \InvalidArgumentException(sprintf('Devices are listed 1 to %d to a page; %d were asked for.', self::MAX_PER_PAGE, $perPage));
        }

        if (!$identity instanceof HasDevices) {
            throw new \LogicException(sprintf('Only identities that implement %s have devices to list; %s does not.', HasDevices::class, $identity::class));
        }

        $now = CarbonImmutable::now();

        /** @var \Illuminate\Pagination\LengthAwarePaginator<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice> $devices */
        $devices = WriteConnection::during($identity, static function () use ($identity, $now, $perPage, $page): LengthAwarePaginator {

            [$query, $device] = IdentityDevices::query($identity);

            self::constrain($query, $device, $now);

            $lastUsed = $device->qualifyColumn($device->getLastUsedAtName());

            return $query
                ->orderByRaw(sprintf('case when %s is null then 1 else 0 end', $device->getConnection()->getQueryGrammar()->wrap($lastUsed)))
                ->orderByDesc($lastUsed)
                ->orderByDesc($device->getQualifiedKeyName())
                ->paginate($perPage, ['*'], 'page', $page);
        });

        return $devices->through(static fn (EloquentDevice&Model $device): DeviceSummary => DeviceSummary::of($device, self::isCurrent($device, $current)));
    }

    /**
     * Whether the listed device is the device bound to the guard: the same
     * class with the same identifier.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $current
     * @return bool
     */
    private static function isCurrent(EloquentDevice&Model $device, ?Device $current): bool
    {
        return $current !== null
            && $current::class === $device::class
            && IdentifierCoercion::matches($current->getDeviceIdentifier(), $device->getDeviceIdentifier());
    }
}
