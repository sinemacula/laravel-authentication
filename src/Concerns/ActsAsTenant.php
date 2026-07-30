<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

/**
 * Provides the default `Tenant` contract implementation sourced from a
 * configurable Eloquent attribute name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ActsAsTenant
{
    /**
     * Return the tenant's stable identifier from the configured attribute.
     *
     * @return mixed
     */
    public function getTenantIdentifier(): mixed
    {
        return $this->getAttribute($this->getTenantIdentifierName());
    }

    /**
     * Column name holding the tenant identifier.
     *
     * @return string
     */
    protected function getTenantIdentifierName(): string
    {
        return 'id';
    }
}
