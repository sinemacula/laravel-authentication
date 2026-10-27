<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Guard;

/**
 * Contextual guard contract.
 *
 * Extends Laravel's `Guard` with the package's contextual surface (identity,
 * principal, device, tenant, type, principal/device setters, contextual
 * `attempt` and `login`). Like `user()`, the accessors and setters resolve the
 * current request on first access, at most once per request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ContextualGuard extends Guard
{
    /**
     * Contextual attempt with optional principal and device pinning.
     *
     * Signature diverges from Laravel's `StatefulGuard::attempt()`: the second
     * and third parameters are contextual pins, not a remember-me flag. This
     * package is stateless-only. Pins are verified against the authenticated
     * identity before they are bound.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return bool
     *
     * @imperative
     */
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Device $device = null): bool;

    /**
     * Bind a fully resolved identity, principal, and optional device.
     *
     * The trusted entry point: the arguments are bound as given, so the caller
     * must already have proven that the principal and device belong to the
     * identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     */
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void;

    /**
     * Return the authenticated identity, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function identity(): ?Identity;

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
     * Return the pinned device, if any, resolving the request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function device(): ?Device;

    /**
     * Return the tenant the active principal acts within, if any, resolving the
     * request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant;

    /**
     * Return the active tenant's type string, if the tenant declares the
     * `HasType` capability, resolving the request on first access.
     *
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function type(): ?string;

    /**
     * Pin the active principal for the current request, resolving the request
     * first so the pin replaces the principal its credential binds rather than
     * being replaced by it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return static
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setPrincipal(Principal $principal): static;

    /**
     * Pin the active device for the current request, resolving the request
     * first so the pin replaces the device its credential binds rather than
     * being replaced by it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return static
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setDevice(Device $device): static;
}
