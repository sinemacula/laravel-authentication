<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\Device;
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
 * The throttle is CarbonImmutable-safe: the "last logged in"
 * comparison narrows to the `CarbonInterface` parent, not the
 * concrete `Carbon` class, so consumer apps that call
 * `Date::use(CarbonImmutable::class)` are not silently broken.
 *
 * The column name is resolved from the device's `ActsAsDevice`
 * accessor when present, so consumers that remap
 * `last_logged_in_at` via the trait's protected override hook have
 * their remapping respected by the listener.
 *
 * No-ops when the device is not an Eloquent model (e.g. a Mockery
 * double in unit tests) or when it has not been persisted yet so the
 * listener remains safe to invoke against any `Device` contract
 * implementation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class UpdateDeviceTimestamp
{
    /** @var int Fallback throttle window (seconds) when the config key is missing or non-positive. */
    private const int DEFAULT_THROTTLE_SECONDS = 60;

    /** @var string Fallback column name when the device does not use `ActsAsDevice`. */
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

        // No-op for non-Eloquent doubles and for new (unpersisted)
        // model instances — there is nothing to update on disk.
        if (!$device instanceof Model || !$device->exists) {
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
     * Whether the last-logged-in timestamp should be updated now.
     * Returns true when the column is unset (first successful login)
     * or when the configured throttle window has elapsed since the
     * last successful persistence.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $device
     * @param  string  $column
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     */
    private function shouldUpdate(Model $device, string $column, CarbonInterface $now): bool
    {
        /** @var mixed $current */
        $current = $device->getAttribute($column);

        if (!$current instanceof CarbonInterface) {
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

    /**
     * Resolve the column name holding the last-logged-in timestamp.
     * Honours `ActsAsDevice::getLastLoggedInName()` when the device
     * implementation exposes it (via a narrow contract check) so
     * consumers that remap the column see the remap respected.
     * Falls back to the package default otherwise.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $device
     * @return string
     */
    private function resolveColumnName(Model $device): string
    {
        if (!$device instanceof Device || !method_exists($device, 'getLastLoggedInName')) {
            return self::DEFAULT_COLUMN;
        }

        /** @var string $column */
        $column = $device->getLastLoggedInName();

        return $column === '' ? self::DEFAULT_COLUMN : $column;
    }
}
