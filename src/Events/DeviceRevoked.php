<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * Dispatched when a device is revoked, ending its session everywhere at once.
 * Fired only by the call that revoked it, not for a device that was already
 * revoked, and only after the surrounding transaction commits, so a revocation
 * that is rolled back is never reported.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeviceRevoked implements ShouldDispatchAfterCommit
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     */
    public function __construct(

        /** Name of the guard that revoked the device. */
        public string $guard,

        /** The device that was revoked. */
        public Device $device,

        /** Why the device was revoked. */
        public RevocationReason $reason,
    ) {}
}
