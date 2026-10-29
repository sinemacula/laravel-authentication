<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * Dispatched when the package revokes a device, ending its session everywhere
 * at once; today that is the refresh exchange revoking a device whose rotated
 * refresh token was replayed. A device an application revokes by writing
 * `revoked_at` itself is not reported.
 *
 * Fired only by the call that revoked the device, not for one that was already
 * revoked, and only once the revocation is committed on the device's own
 * connection: at once when that connection has no open transaction, after its
 * transaction commits otherwise, and never for a revocation that is rolled
 * back. A transaction on another connection neither delays nor cancels it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeviceRevoked
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
