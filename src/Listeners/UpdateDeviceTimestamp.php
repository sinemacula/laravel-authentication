<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;

/**
 * Updates the device's `last_logged_in_at` on authentication, debounced by a
 * configurable throttle. Only persisted `EloquentDevice` models participate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UpdateDeviceTimestamp
{
    /** @var int Fallback throttle window (seconds). */
    private const int DEFAULT_THROTTLE_SECONDS = 60;

    /** @var string Fallback column name. */
    private const string DEFAULT_COLUMN = 'last_logged_in_at';

    /**
     * Handle the DeviceAuthenticated event.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\DeviceAuthenticated  $event
     * @return void
     */
    public function __invoke(DeviceAuthenticated $event): void
    {
        $device = $event->device;

        // No-op for generic device payloads and unpersisted instances.
        if (!$device instanceof EloquentDevice || !$device instanceof Model || !$device->exists) {
            return;
        }

        $now    = Carbon::now();
        $column = $this->resolveColumnName($device);

        if (!$this->shouldUpdate($device, $column, $now)) {
            return;
        }

        $device->newQuery()
            ->whereKey($device->getKey())
            ->update([$column => $now]);

        $device->setAttribute($column, $now);
    }

    /**
     * Resolve the column name holding the last-logged-in timestamp. Honours the
     * explicit `EloquentDevice` column-name contract and falls back to the
     * package default only for defensive empty-string overrides.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return string
     */
    private function resolveColumnName(EloquentDevice $device): string
    {
        $column = $device->getLastLoggedInName();

        return $column === '' ? self::DEFAULT_COLUMN : $column;
    }

    /**
     * Whether the last-logged-in timestamp should be updated now. Returns true
     * on first login or when the configured throttle window has elapsed since
     * the last persistence.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $device
     * @param  string  $column
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     */
    private function shouldUpdate(Model $device, string $column, CarbonInterface $now): bool
    {
        $current = $device->getAttribute($column);

        if (!$current instanceof CarbonInterface) {
            return true;
        }

        $windowSeconds = Config::integer(
            'authentication.device.last_seen_throttle_seconds',
            self::DEFAULT_THROTTLE_SECONDS,
        );

        if ($windowSeconds <= 0) {
            return true;
        }

        return $current->diffInSeconds($now, true) >= $windowSeconds;
    }
}
