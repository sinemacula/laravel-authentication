<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Dispatched when a session switches the principal it acts as on the same
 * device (`switchPrincipal()`): the device records the new principal, its
 * refresh credential was rotated, and the access tokens issued for the previous
 * principal stopped working.
 *
 * Dispatched once the switch is committed on the device's own connection: at
 * once when that connection has no open transaction, after its transaction
 * commits otherwise, and never for a switch that is rolled back. A switch to
 * the principal the device already records rotates the credential like a
 * refresh and dispatches nothing.
 *
 * The context carries the guard, the client, the identity, the new principal
 * and its tenant, the device and its method. The previous principal is
 * described by the type and identifier the device recorded, taken when the
 * event is built, and by the principal itself when it still resolves for the
 * identity (`null` otherwise).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PrincipalSwitched implements AuthenticationEvent
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $previousPrincipal
     * @param  ?string  $previousPrincipalType
     * @param  ?string  $previousPrincipalId
     */
    public function __construct(

        /** Who switched, to which principal, on which device, and from which client. */
        public EventContext $context,

        /** The principal the session acted as before, when it still resolves. */
        public ?Principal $previousPrincipal,

        /** The type the device recorded for the previous principal. */
        public ?string $previousPrincipalType,

        /** The identifier the device recorded for the previous principal. */
        public ?string $previousPrincipalId,
    ) {}

    /**
     * Return who switched, to which principal, and on which device.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
