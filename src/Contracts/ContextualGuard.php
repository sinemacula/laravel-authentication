<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Guard;

/**
 * Contextual guard contract.
 *
 * Extends Laravel's `Guard` with the package's contextual surface
 * (identity, principal, device, organization, scope, internal/external
 * helpers, principal/device setters, contextual `attempt` and `login`).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
interface ContextualGuard extends Guard
{
    /**
     * Contextual attempt — accepts an optional principal and device pinning.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return bool
     */
    public function attempt(array $credentials, ?Principal $principal = null, ?Device $device = null): bool;

    /**
     * Contextual login — bind a fully resolved identity, principal,
     * and optional device.
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
     * Return the organization the active principal acts within, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Organization
     */
    public function organization(): ?Organization;

    /**
     * Return the active organization scope string, if any.
     *
     * @return ?string
     */
    public function scope(): ?string;

    /**
     * Return whether the active scope is the configured internal scope.
     *
     * @return bool
     */
    public function isInternal(): bool;

    /**
     * Return whether the active scope is the configured external scope.
     *
     * @return bool
     */
    public function isExternal(): bool;

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
