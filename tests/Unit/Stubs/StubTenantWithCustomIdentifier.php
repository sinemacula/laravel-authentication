<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

/**
 * Tenant variant that overrides the identifier column to `tenant_uuid`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubTenantWithCustomIdentifier extends StubTenant
{
    /**
     * Source the tenant identifier from a different column.
     *
     * @return string
     */
    #[\Override]
    protected function getTenantIdentifierName(): string
    {
        return 'tenant_uuid';
    }
}
