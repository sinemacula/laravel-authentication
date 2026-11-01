<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Concerns\SerializesLiveModels;

/**
 * Dispatched when a session switches the principal it acts as, its active
 * tenant, or both (`switchTo()`): the session records the new principal and
 * tenant, its refresh credential was rotated, and every access token issued
 * before the switch stopped working. `principalChanged` and `tenantChanged` say
 * which changed; at least one did.
 *
 * Dispatched once the switch is committed on the session's own connection: at
 * once when that connection has no open transaction, after its transaction
 * commits otherwise, and never for a switch that is rolled back. A switch to
 * the principal and tenant the session already records rotates the credential
 * like a refresh and dispatches nothing.
 *
 * The context carries the guard, the client, the identity, the new principal
 * and the tenant it now acts in, the session and its method. The previous
 * principal is described by the morph class and identifier the session
 * recorded, taken when the event is built, and by the principal itself when it
 * still resolves for the identity (`null` otherwise); the previous tenant by
 * the identifier the session recorded (`null` for none). Like the context's
 * models, the previous principal is a live model: after a queue it is fetched
 * again, or `null` when its row is gone or it is not an Eloquent model; the
 * recorded morph class and identifiers are the record.
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
     * @param  ?string  $previousTenantId
     * @param  bool  $principalChanged
     * @param  bool  $tenantChanged
     */
    public function __construct(

        /** Who switched, to which principal and tenant, in which session, and from which client. */
        public EventContext $context,

        /** The principal the session acted as before, when it still resolves. */
        public ?Principal $previousPrincipal,

        /** The morph class the session recorded for the previous principal. */
        public ?string $previousPrincipalMorphClass,

        /** The identifier the session recorded for the previous principal. */
        public ?string $previousPrincipalId,

        /** The identifier the session recorded for the tenant it acted in before, `null` for none. */
        public ?string $previousTenantId,

        /** Whether the switch changed the principal the session acts as. */
        public bool $principalChanged,

        /** Whether the switch changed the session's active tenant. */
        public bool $tenantChanged,
    ) {}

    /**
     * Return who switched, to which principal and tenant, and in which session.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
