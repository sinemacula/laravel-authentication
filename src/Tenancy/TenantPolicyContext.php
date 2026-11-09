<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * What a tenant authentication policy is asked about: the application (the
 * guard), the identity, the principal acting in the tenant, the tenant, and the
 * session, or `null` before one is written. Exemptions are the policy's own
 * answer, decided from these.
 *
 * `connectionId()` is the connection the session was established through, or
 * `null` when no provider established it. It is found when first asked, and at
 * most once however often it is, by the closure the context is built with: a
 * policy that never asks, and a judgement that names no connections, cost no
 * read of the session's provenance. Built without a closure, as a policy under
 * test is, it is `null`; pass `fn (): ?string => 'conn-a'` to give it one.
 *
 * It is read while the policy answers, not after: when the check ends, a
 * connection not yet found is never found, and asking for it throws a
 * `LogicException`, since the session's key may name another session by then. A
 * policy that keeps its context may still read a connection it had found.
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
     * provider established it: found on the first call and kept, and only while
     * the check that made the context is running.
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
     * End the check that made the context: the connection, if not yet found, is
     * never found.
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
