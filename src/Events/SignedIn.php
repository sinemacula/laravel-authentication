<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched when the session service starts a session: a real sign-in, with
 * the method that proved who signed in, as opposed to Laravel's `Login` and
 * `Authenticated`, which also fire when a refresh or a bearer request binds the
 * guard. A refresh dispatches `Refreshed` instead. `attempt()` starts no
 * session and never dispatches it; Laravel's `Login` reports its sign-ins.
 *
 * Dispatched once the session is committed on the device's own connection: at
 * once when that connection has no open transaction, after its transaction
 * commits otherwise, and never for a sign-in that is rolled back. It follows
 * `DeviceCreated` when the sign-in created the device.
 *
 * The context carries the guard, the client the sign-in came from, the
 * identity, principal, tenant and device, and the method. Never carries a
 * credential or a token.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignedIn implements AuthenticationEvent
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  bool  $deviceCreated
     * @param  bool  $refresh
     */
    public function __construct(

        /** Who signed in, as which principal, on which device, how, and from which client. */
        public EventContext $context,

        /** Whether the device was created, rather than an existing one of the client continued. */
        public bool $deviceCreated,

        /** Whether a refresh renewed the session, rather than a sign-in starting it. */
        public bool $refresh,
    ) {}

    /**
     * Return who signed in, as which principal, on which device, and how.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
