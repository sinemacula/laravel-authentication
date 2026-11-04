<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;

/**
 * Dispatched when an active session that fell short of a requirement during a
 * request (a refresh, a switch to a tenant whose policy asks for a further
 * factor the session lacks, the removal of the factor that met it, or another
 * change of the identity's factors that leaves it short) returns to pending
 * instead of being re-issued its pair: from then on its access and refresh
 * tokens are refused, and it holds only the pending credential the call handed
 * out until it activates again, which dispatches `SessionActivated`.
 *
 * Dispatched once the return is committed on the session's own connection: at
 * once when that connection has no open transaction, after its transaction
 * commits otherwise, and never for one that is rolled back.
 *
 * The context carries the destination the session waits to activate in: its
 * principal and active tenant. The previous principal and tenant are named when
 * the destination changed them (a switch), and are `null` otherwise. Never
 * carries the pending credential, a token or any other secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionReturnedToPending implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  list<string>  $requires
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  ?string  $previousPrincipalType
     * @param  ?string  $previousPrincipalId
     * @param  ?string  $previousTenantId
     */
    public function __construct(

        /** The session, the destination it waits to activate in, and the client. */
        public EventContext $context,

        /** What the session waits on, in order. */
        public array $requires,

        /** When the pending credential, and the session with it, ends unless it activates. */
        public CarbonImmutable $expiresAt,

        /** The flow the shortfall was found in: a refresh, a switch, or a factor's removal or other change (`factor_change`). */
        public AuthenticationFlow $flow,

        /** The morph class of the principal the session acted as, when the destination changed it. */
        public ?string $previousPrincipalType = null,

        /** The id of the principal the session acted as, when the destination changed it. */
        public ?string $previousPrincipalId = null,

        /** The id of the tenant the session was active in, when the destination changed it. */
        public ?string $previousTenantId = null,
    ) {}

    /**
     * Return the session and the destination it waits to activate in.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
