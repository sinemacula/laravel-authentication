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
     * Return the bound device, if any, resolving the request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function device(): ?Device;

    /**
     * Return the tenant the active principal acts within, if any, resolving the
     * request on first access. Throws as `ContextualGuard::tenant()` does.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant;

    /**
     * Bind a session the flow started as a sign-in (`Validated`, `Login` and
     * the bind events).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     *
     * @throws \LogicException
     */
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void;

    /**
     * Bind a session the flow verified itself as a sign-in (`Validated`,
     * `Login` and the bind events), with the tenant the flow's activity check
     * loaded and the sign-in method it reports, as a refresh binds the session
     * it rotated.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @return void
     */
    public function loginVerified(Identity $identity, Principal $principal, ?Device $device, ?Tenant $tenant, ?string $method): void;

    /**
     * Bind a session the flow moved as the request's authentication, not as a
     * sign-in (the bind events only).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?list<string>  $scopes
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function authenticateAs(Identity $identity, Principal $principal, ?Device $device = null, ?array $scopes = null): void;

    /**
     * Forget the bound identity, principal and device, with no event, and keep
     * the guard signed out for the rest of the request.
     *
     * @return static
     */
    public function forgetUser(): static;
}
