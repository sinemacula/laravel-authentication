<?php

declare(strict_types=1);

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
     * @param array<string, mixed> $credentials
     */
    public function attempt(array $credentials, ?Principal $principal = null, ?Device $device = null): bool;

    /**
     * Contextual login — bind a fully resolved identity, principal,
     * and optional device.
     */
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void;

    /** Return the authenticated identity, if any. */
    public function identity(): ?Identity;

    /** Return the active principal, if any. */
    public function principal(): ?Principal;

    /** Return the pinned device, if any. */
    public function device(): ?Device;

    /** Return the organization the active principal acts within, if any. */
    public function organization(): ?Organization;

    /** Return the active organization scope string, if any. */
    public function scope(): ?string;

    /** Return whether the active scope is the configured internal scope. */
    public function isInternal(): bool;

    /** Return whether the active scope is the configured external scope. */
    public function isExternal(): bool;

    /** Pin the active principal for the current request. */
    public function setPrincipal(Principal $principal): static;

    /** Pin the active device for the current request. */
    public function setDevice(Device $device): static;
}
