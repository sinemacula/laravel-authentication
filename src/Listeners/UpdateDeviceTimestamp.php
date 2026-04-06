<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;

/**
 * Listener: update the bound device's `last_logged_in_at` when a
 * device is authenticated.
 *
 * No-ops when the device is not an Eloquent model (e.g. a Mockery
 * double in unit tests) so the listener remains safe to invoke
 * against any `Device` contract implementation.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class UpdateDeviceTimestamp
{
    /**
     * Handle the DeviceAuthenticated event.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\DeviceAuthenticated $event The dispatched event carrying the authenticated device.
     * @return void
     */
    public function handle(DeviceAuthenticated $event): void
    {
        $device = $event->device;

        // No-op for non-Eloquent doubles and for new (unpersisted)
        // model instances — there is nothing to update on disk.
        if (! $device instanceof Model || ! $device->exists) {
            return;
        }

        $device->forceFill([
            'last_logged_in_at' => Carbon::now(),
        ])->save();
    }
}
