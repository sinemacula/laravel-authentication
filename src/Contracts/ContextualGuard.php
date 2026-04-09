<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Guard;

/**
 * Contextual guard contract.
 *
 * Extends Laravel's `Guard` with the package's contextual surface (identity,
 * principal, device, tenant, type, principal/device setters, contextual
 * `attempt` and `login`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface ContextualGuard extends Guard
{
    /**
     * Contextual attempt with optional principal and device pinning.
     *
     * Signature diverges from Laravel's `StatefulGuard::attempt()`: the second
     * and third parameters are contextual pins, NOT a remember-me flag - this
     * package is stateless-only. Safe at the type level because
     * `ContextualGuard` extends `Guard`, not `StatefulGuard`. Consumers needing
     * stateful semantics should keep using `SessionGuard`.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return bool
     */
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Device $device = null): bool;

    /**
     * Bind a fully resolved identity, principal, and optional device.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     */
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void;

    /**
     * Return the authenticated identity, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    public function identity(): ?Identity;

    /**
     * Return the active principal, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function principal(): ?Principal;

    /**
     * Return the pinned device, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    public function device(): ?Device;

    /**
     * Return the tenant the active principal acts within, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    public function tenant(): ?Tenant;

    /**
     * Return the active tenant's type string, if the tenant declares the
     * `HasType` capability.
     *
     * @return ?string
     */
    public function type(): ?string;

    /**
     * Pin the active principal for the current request.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return static
     */
    public function setPrincipal(Principal $principal): static;

    /**
     * Pin the active device for the current request.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return static
     */
    public function setDevice(Device $device): static;
}
