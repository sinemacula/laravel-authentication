<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;

/**
 * Listener: update the bound device's `last_logged_in_at` when a
 * device is authenticated.
 *
 * Debounced by a configurable throttle window so a high-throughput
 * API that binds the same device on every authenticated request does
 * not produce a per-request hot-spot write on the device row. The
 * update uses an atomic `update()` against the row, not a full
 * `forceFill+save`, so no in-memory model mutations sneak into the
 * persisted state.
 *
 * No-ops when the device is not an Eloquent model (e.g. a Mockery
 * double in unit tests) or when it has not been persisted yet so the
 * listener remains safe to invoke against any `Device` contract
 * implementation.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class UpdateDeviceTimestamp
{
    /** @var int Fallback throttle window (seconds) when the config key is missing or non-positive. */
    private const int DEFAULT_THROTTLE_SECONDS = 60;

    /**
     * Handle the DeviceAuthenticated event.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\DeviceAuthenticated  $event
     * @return void
     */
    public function __invoke(DeviceAuthenticated $event): void
    {
        $device = $event->device;

        // No-op for non-Eloquent doubles and for new (unpersisted)
        // model instances — there is nothing to update on disk.
        if (!$device instanceof Model || !$device->exists) {
            return;
        }

        $now = Carbon::now();

        if (!$this->shouldUpdate($device, $now)) {
            return;
        }

        $device->newQuery()
            ->whereKey($device->getKey())
            ->update(['last_logged_in_at' => $now]);

        $device->setAttribute('last_logged_in_at', $now);
    }

    /**
     * Whether the last-logged-in timestamp should be updated now.
     * Returns true when the column is unset (first successful login)
     * or when the configured throttle window has elapsed since the
     * last successful persistence.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $device
     * @param  \Carbon\Carbon  $now
     * @return bool
     */
    private function shouldUpdate(Model $device, Carbon $now): bool
    {
        /** @var mixed $current */
        $current = $device->getAttribute('last_logged_in_at');

        if (!$current instanceof Carbon) {
            return true;
        }

        $windowSeconds = Config::integer(
            'laravel-authentication.device.last_seen_throttle_seconds',
            self::DEFAULT_THROTTLE_SECONDS,
        );

        if ($windowSeconds <= 0) {
            return true;
        }

        return $current->diffInSeconds($now, true) >= $windowSeconds;
    }
}
