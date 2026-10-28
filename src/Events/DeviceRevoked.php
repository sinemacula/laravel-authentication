<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
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
 * The context's guard is the device's own and its device is never `null`; the
 * identity, principal and tenant are carried when the revoking flow knew them
 * (a replay is caught before the owner is loaded, so it carries none).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeviceRevoked implements AuthenticationEvent
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     */
    public function __construct(

        /** The revoked device, its guard, and whose session it held as far as known. */
        public EventContext $context,

        /** Why the device was revoked. */
        public RevocationReason $reason,
    ) {}

    /**
     * Return the revoked device and whose session it held.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
