<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * What a session flow may do to its guard's bound state: read what the request
 * is authenticated as, bind a session it started or refreshed, and forget the
 * binding when it signs the session out. The package's guards implement it
 * through `AbstractGuard`, so a session flow needs no guard class.
 *
 * The four readers resolve lazily, as the guard's own accessors do: the first
 * of them to be called on a request resolves the request's credential, at most
 * once per request, so a sign-out reads the session the request carries without
 * having authenticated it first.
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
     * Return the active tenant, if any, resolving the request on first access,
     * as `ContextualGuard::tenant()` does.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant;

    /**
     * Bind a session the flow started as a sign-in (`Validated`, `Login` and
     * the bind events).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     *
     * @throws \LogicException
     */
    public function login(Identity $identity, Principal $principal, ?Session $session = null): void;

    /**
     * Bind a session the flow verified itself as a sign-in (`Validated`,
     * `Login` and the bind events), with the tenant the flow's activity check
     * loaded and the sign-in method it reports, as a refresh binds the session
     * it rotated.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @return void
     */
    public function loginVerified(Identity $identity, Principal $principal, ?Session $session, ?Tenant $tenant, ?string $method): void;

    /**
     * Bind a session the flow moved as the request's authentication, not as a
     * sign-in (the bind events only), in the active tenant given, or, with none
     * given, the one the session records (the principal's own without a
     * session).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?list<string>  $scopes
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function authenticateAs(Identity $identity, Principal $principal, ?Session $session = null, ?array $scopes = null, ?Tenant $tenant = null): void;

    /**
     * Forget the bound identity, principal and session, with no event, and keep
     * the guard signed out for the rest of the request.
     *
     * @return static
     */
    public function forgetUser(): static;

    /**
     * Forget the binding as `forgetUser()` does when it is bound to the
     * session, without resolving the request: a flow that takes the session out
     * of the active state calls it, so the request stops acting in it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     */
    public function forgetSession(Session $session): void;

    /**
     * Forget the binding as `forgetUser()` does when it is bound to the
     * identity, whichever session it acts in, without resolving the request: a
     * flow that ends every session of the identity calls it, so the request
     * stops acting as it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return void
     */
    public function forgetIdentity(Identity $identity): void;

    /**
     * Forget the authentication context the guard holds, keeping the binding,
     * when it is bound to the session, without resolving the request: a flow
     * that changed the session's proofs calls it once the change commits or
     * rolls back, so the next ask builds the context from them.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     */
    public function forgetAuthenticationContext(Session $session): void;
}
