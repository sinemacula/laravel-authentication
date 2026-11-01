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
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TenantPolicyContext
{
    /**
     * Constructor.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
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
    ) {}
}
