<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Capability contract: identity can report an active / inactive state.
 *
 * Optional supplement to `Identity`. When an identity implements this
 * interface, the package's guards will consult `isActive()` during
 * both the bearer-token resolution path (`JwtGuard::user()`) and the
 * credential-validation path (`BasicGuard::user()` / `attempt()`) and
 * reject the authentication if it returns `false`.
 *
 * Use this to honour banned / suspended / soft-deleted identities
 * without relying on short access-token lifetimes alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface CanBeActive
{
    /**
     * Whether the identity is currently eligible to authenticate.
     *
     * @return bool
     */
    public function isActive(): bool;
}
