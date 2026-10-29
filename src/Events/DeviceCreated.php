<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Dispatched when the session service creates a device for a sign-in, once the
 * new row is committed on the device's own connection (never for one that is
 * rolled back), just before `SignedIn`. A sign-in that continues an existing
 * device of the same client does not dispatch it.
 *
 * Queued listeners get the identity, principal, tenant and device re-fetched
 * from the database, as Laravel's `SerializesModels` does; the method and the
 * client are snapshots. Never carries a credential or a token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeviceCreated
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     */
    public function __construct(

        /** Name of the guard the device's session belongs to. */
        public string $guard,

        /** Identity that owns the device. */
        public Identity $identity,

        /** Principal the device's session acts as. */
        public Principal $principal,

        /** Tenant the principal acts within, if any. */
        public ?Tenant $tenant,

        /** The device that was created. */
        public Device $device,

        /** Name of the sign-in method that created it. */
        public string $method,

        /** Client the device was created for. */
        public ClientContext $client,
    ) {}
}
