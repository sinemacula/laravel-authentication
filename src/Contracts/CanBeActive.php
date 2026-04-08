<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Capability contract: identity can report an active / inactive state.
 *
 * Optional supplement to `Identity`. When implemented, guards consult
 * `isActive()` on both the bearer-token and credential-validation
 * paths and reject authentication if it returns `false`. Use this to
 * honour banned / suspended / soft-deleted identities without
 * relying on short access-token lifetimes alone.
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
