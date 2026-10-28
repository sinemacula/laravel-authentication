<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Capability contract: a model can report an active / inactive state.
 *
 * Optional supplement to `Identity`, `Principal`, and `Tenant`. Activation is
 * opt-in: a model that does not implement this contract is always active, and
 * one that does is consulted on the credential, bearer-token and refresh paths,
 * which reject authentication when `isActive()` returns `false`. A deactivated
 * tenant rejects every principal acting within it. Use this to honour banned /
 * suspended / soft-deleted accounts, memberships, or tenants without relying on
 * short access-token lifetimes alone. `ProvidesActiveState` implements it from
 * a declared column.
 *
 * The activity check runs `isActive()` inside `WriteConnection::during()` for
 * the subject: model reads on any connection, and query-builder reads on the
 * subject's own connection when it is an Eloquent model, go to the write
 * connection; any other query-builder read must pin itself (see
 * `Database\WriteConnection`).
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
