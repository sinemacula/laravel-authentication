<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Capability contract: tenant can report a categorical type string.
 *
 * Optional supplement to `Tenant`. When implemented, the contextual guard
 * exposes the value via `Auth::type()` so consumers can branch on broad tenant
 * categories (e.g. `"staff"`, `"customer"`, `"pro"`, `"free"`) without reaching
 * into the concrete model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface HasType
{
    /**
     * Return the tenant's type string.
     *
     * @return string
     */
    public function getType(): string;
}
