<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * The auth manager's reads of the active guard's identity, principal, session,
 * tenant and scopes.
 *
 * Kept in a trait only to hold the manager under the per-class method limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsActiveGuard
{
    /**
     * The active identity, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function identity(): ?Identity
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->identity() : null;
    }

    /**
     * The active principal, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principal(): ?Principal
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->principal() : null;
    }

    /**
     * The active session, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function session(): ?Session
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->session() : null;
    }

    /**
     * The active tenant, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->tenant() : null;
    }

    /**
     * The scopes the request's credential grants; `null` for a human session.
     *
     * @return ?list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function scopes(): ?array
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->scopes() : null;
    }
}
