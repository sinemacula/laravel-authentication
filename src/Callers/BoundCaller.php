<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Callers;

use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;

/**
 * What a guard is already bound to, read without resolving the request
 * (`ContextualGuard::boundCaller()`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BoundCaller
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Context\Enums\CredentialKind  $credentialKind
     * @param  ?string  $credentialId
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null  $tenant
     */
    public function __construct(

        /** The bound identity. */
        public Identity $identity,

        /** The bound principal, or `null` for an identity bound without one. */
        public ?Principal $principal,

        /** The bound session, or `null` for a credential without one (an access-only token, an API key). */
        public ?Session $session,

        /** The kind of credential the guard authenticated, or `null` for a bind that authenticated none (a sign-in, a trusted bind). */
        public ?CredentialKind $credentialKind,

        /** The id of the API key the credential is or was issued for, never the key itself; `null` for any other credential. */
        #[\SensitiveParameter]
        public ?string $credentialId,

        /** The active tenant, the reason it cannot be loaded, or `null` for none. */
        private Tenant|TenantUnavailableException|null $tenant,
    ) {}

    /**
     * The active tenant, or `null` when the caller acts in none.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function tenant(): ?Tenant
    {
        if ($this->tenant instanceof TenantUnavailableException) {
            throw $this->tenant;
        }

        return $this->tenant;
    }
}
