<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * Dispatched when the package revokes a device, ending its session everywhere
 * at once: a sign-out (`signOut()`, `logout()`), a revocation the application
 * asks the session service for (`revokeDevice()`, `revokeDevices()`,
 * `revokePrincipalDevices()`, `signOutEverywhere()` and the security-change
 * methods), and a refresh or switch that caught a replayed refresh token. A
 * device an application revokes by writing `revoked_at` itself is not reported.
 *
 * Fired only by the call that revoked the device, not for one that was already
 * revoked, and only once the revocation is committed on the device's own
 * connection: at once when that connection has no open transaction, after its
 * transaction commits otherwise, and never for a revocation that is rolled
 * back. A transaction on another connection neither delays nor cancels it.
 *
 * The context's guard is the device's own and its device is never `null`. The
 * identity, principal and tenant are those the revoking flow holds; the
 * snapshot of an identity or principal it does not hold is the owner or
 * principal the device row records (a replay is caught before the owner is
 * loaded, so its models are `null` and its snapshots name what the row
 * records). The tenant is carried only by `signOut()` and
 * `tenantDeactivated()`, since devices record none.
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
