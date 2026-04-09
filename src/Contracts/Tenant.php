<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Tenant contract.
 *
 * Describes an isolation boundary a principal acts within in the 3D
 * model - a company, workspace, project, or any other domain-specific
 * container the consumer models.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface Tenant
{
    /**
     * Return the tenant's stable identifier (typically the model key).
     *
     * @return mixed
     */
    public function getTenantIdentifier(): mixed;
}
