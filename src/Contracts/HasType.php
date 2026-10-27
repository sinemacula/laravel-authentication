<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Capability contract: a principal or a tenant can report a categorical type
 * string.
 *
 * Optional supplement to `Principal` and `Tenant`. A principal's type is its
 * own when it implements this contract and reports one, otherwise its tenant's
 * (see `Audience\PrincipalType`). The type labels broad categories of caller
 * (e.g. `"staff"`, `"client_admin"`, `"service"`): access tokens carry it in
 * their `pty` claim, `Auth::type()` returns it, and a guard can admit only some
 * types and give each its own token and session lifetimes. An empty string
 * reports no type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasType
{
    /**
     * Return the model's type string, or an empty string for none.
     *
     * @return string
     */
    public function getType(): string;
}
