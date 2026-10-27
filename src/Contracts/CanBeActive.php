<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Capability contract: a model can report an active / inactive state.
 *
 * Optional supplement to `Identity` and `Principal`. Activation is opt-in: a
 * model that does not implement this contract is always active, and one that
 * does is consulted on the credential, bearer-token and refresh paths, which
 * reject authentication when `isActive()` returns `false`. Use this to honour
 * banned / suspended / soft-deleted accounts or memberships without relying on
 * short access-token lifetimes alone. `ProvidesActiveState` implements it from
 * a declared column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CanBeActive
{
    /**
     * Whether the model is currently eligible to authenticate.
     *
     * @return bool
     */
    public function isActive(): bool;
}
