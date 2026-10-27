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
 * Dispatched when the session service starts a session: a real sign-in, with
 * the method that proved who signed in, as opposed to Laravel's `Login` and
 * `Authenticated`, which also fire when a refresh or a bearer request binds the
 * guard. A refresh dispatches `Refreshed` instead.
 *
 * Dispatched once the session is committed on the device's own connection: at
 * once when that connection has no open transaction, after its transaction
 * commits otherwise, and never for a sign-in that is rolled back. It follows
 * `DeviceCreated` when the sign-in created the device.
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
final readonly class SignedIn
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
     * @param  bool  $deviceCreated
     */
    public function __construct(

        /** Name of the guard the session belongs to. */
        public string $guard,

        /** Identity that signed in. */
        public Identity $identity,

        /** Principal the session acts as. */
        public Principal $principal,

        /** Tenant the principal acts within, if any. */
        public ?Tenant $tenant,

        /** Device holding the session. */
        public Device $device,

        /** Name of the sign-in method that started the session. */
        public string $method,

        /** Client the sign-in came from. */
        public ClientContext $client,

        /** Whether the device was created, rather than an existing one of the client continued. */
        public bool $deviceCreated,
    ) {}
}
