<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * An isolation boundary a principal acts within, such as a company or
 * workspace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Tenant
{
    /**
     * Return the tenant's stable identifier.
     *
     * @return mixed
     */
    public function getTenantIdentifier(): mixed;
}
