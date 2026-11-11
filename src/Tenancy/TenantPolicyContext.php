<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * What a tenant authentication policy is asked about.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TenantPolicyContext
{
    /** @var \SineMacula\Laravel\Authentication\Tenancy\ConnectionLookup Finds the connection on the first ask. */
    private ConnectionLookup $connection;

    /**
     * Constructor.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\Closure(): ?string  $connectionId
     */
    public function __construct(

        /** The application (the guard) the session is on. */
        public string $application,

        /** The identity acting. */
        public Identity $identity,

        /** The principal acting in the tenant. */
        public Principal $principal,

        /** The tenant whose policy is asked. */
        public Tenant $tenant,

        /** The session, or `null` before one is written. */
        public ?Session $session,

        // Finds the connection the session was established through, when asked.
        ?\Closure $connectionId = null,
    ) {
        $this->connection = new ConnectionLookup($connectionId);
    }

    /**
     * The connection the session was established through, or `null` when no
     * provider established it.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function connectionId(): ?string
    {
        return $this->connection->connectionId();
    }

    /**
     * End the check that made the context.
     *
     * @return void
     *
     * @internal
     */
    public function expire(): void
    {
        $this->connection->expire();
    }
}
