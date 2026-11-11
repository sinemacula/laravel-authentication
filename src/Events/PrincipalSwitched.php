<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

/**
 * Dispatched once a session's switch of principal, active tenant or both is
 * committed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PrincipalSwitched implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?string  $previousPrincipalType
     * @param  ?string  $previousPrincipalId
     * @param  ?string  $previousTenantId
     * @param  bool  $principalChanged
     * @param  bool  $tenantChanged
     */
    public function __construct(

        /** Who switched, to which principal and tenant, in which session, and from which client. */
        public EventContext $context,

        /** The morph class the session recorded for the previous principal. */
        public ?string $previousPrincipalType,

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
