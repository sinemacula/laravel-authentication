<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * What a session flow may do to its guard's bound state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface GuardBinding
{
    /**
     * Return the authenticated identity, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function user(): ?Identity;

    /**
     * Return the active principal, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principal(): ?Principal;

    /**
     * Return the bound session, if any, resolving the request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function session(): ?Session;

    /**
     * Return the active tenant, if any, resolving the request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant;

    /**
     * Bind a session the flow started and reported as a sign-in.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \LogicException
     */
    public function loginStarted(Identity $identity, Principal $principal, ?Session $session = null, ?ClientContext $client = null): void;

    /**
     * Bind a session the flow verified itself as a sign-in, as a refresh binds
     * the session it rotated.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    public function loginVerified(Identity $identity, Principal $principal, ?Session $session, ?Tenant $tenant, ?string $method, ?ClientContext $client = null): void;

    /**
     * Bind a session the flow moved as the request's authentication, without
     * the sign-in events.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?list<string>  $scopes
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function authenticateAs(
        Identity $identity,
        Principal $principal,
        ?Session $session = null,
        ?array $scopes = null,
        ?Tenant $tenant = null,
        ?ClientContext $client = null,
    ): void;

    /**
     * Forget the bound identity, principal and session, with no event, and keep
     * the guard signed out for the rest of the request.
     *
     * @return static
     */
    public function forgetUser(): static;

    /**
     * Forget the binding as `forgetUser()` does when it is bound to the
     * session, without resolving the request.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     */
    public function forgetSession(Session $session): void;

    /**
     * Forget the binding as `forgetUser()` does when it is bound to the
     * identity, unless it is bound to the session kept, without resolving the
     * request.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $kept
     * @return void
     */
    public function forgetIdentity(Identity $identity, ?Session $kept = null): void;

    /**
     * Forget the authentication context the guard holds for the session,
     * keeping the binding.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     */
    public function forgetAuthenticationContext(Session $session): void;

    /**
     * The bound state's version, replaced whenever that state changes.
     *
     * @return int
     */
    public function boundStateVersion(): int;
}
