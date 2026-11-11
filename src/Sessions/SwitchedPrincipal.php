<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;

/**
 * A session a switch re-issued the pair of, with what it recorded before and
 * what the switch changed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SwitchedPrincipal
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh  $session
     * @param  ?string  $previousType
     * @param  ?string  $previousId
     * @param  ?string  $previousTenantId
     * @param  bool  $principalChanged
     * @param  bool  $tenantChanged
     */
    public function __construct(

        /** The session, acting as the destination, with its new pair. */
        public ExchangedRefresh $session,

        /** The principal's morph type the session recorded before. */
        public ?string $previousType,

        /** The principal identifier the session recorded before. */
        public ?string $previousId,

        /** The active tenant's identifier the session recorded before. */
        public ?string $previousTenantId,

        /** Whether this call changed the principal, rather than keeping the one recorded or answering a retry. */
        public bool $principalChanged,

        /** Whether this call changed the active tenant, rather than keeping the one recorded or answering a retry. */
        public bool $tenantChanged,
    ) {}

    /**
     * Whether this call changed the principal or the active tenant.
     *
     * @return bool
     */
    public function changed(): bool
    {
        return $this->principalChanged || $this->tenantChanged;
    }
}
