<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Concerns\SerializesLiveModels;

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
 * described by the morph class and identifier the device recorded, taken when
 * the event is built, and by the principal itself when it still resolves for
 * the identity (`null` otherwise). Like the context's models, the previous
 * principal is a live model: after a queue it is fetched again, or `null` when
 * its row is gone or it is not an Eloquent model; the recorded morph class and
 * identifier are the record.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PrincipalSwitched implements AuthenticationEvent
{
    use SerializesLiveModels;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $previousPrincipal
     * @param  ?string  $previousPrincipalMorphClass
     * @param  ?string  $previousPrincipalId
     */
    public function __construct(

        /** Who switched, to which principal, on which device, and from which client. */
        public EventContext $context,

        /** The principal the session acted as before, when it still resolves. */
        public ?Principal $previousPrincipal,

        /** The morph class the device recorded for the previous principal. */
        public ?string $previousPrincipalMorphClass,

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
