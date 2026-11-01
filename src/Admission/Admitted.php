<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * What the guard admitted, whichever flow asked (a sign-in, a refresh, a bearer
 * token, an API key, a client credentials exchange): the active identity, the
 * active principal it acts as, the active tenant that principal acts within, if
 * any, and the session the flow is on, once one is known: a sign-in's is the
 * session the client proved it holds, which its new session replaces.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Admitted
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     */
    public function __construct(

        /** The identity admitted. */
        public Identity $identity,

        /** The principal it acts as. */
        public Principal $principal,

        /** The tenant the principal acts within, if any. */
        public ?Tenant $tenant,

        /** The session the flow is on, if any. */
        public ?Session $session = null,
    ) {}

    /**
     * The same admission, on the given session.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return self
     */
    public function on(?Session $session): self
    {
        return new self($this->identity, $this->principal, $this->tenant, $session);
    }
}
