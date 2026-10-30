<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

/**
 * Tenant variant whose identifier column builds on the trait's default:
 * `tenant_id`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubTenantWithPrefixedIdentifier extends StubTenant
{
    /**
     * Prefix the default identifier column.
     *
     * @return string
     */
    #[\Override]
    protected function getTenantIdentifierName(): string
    {
        return 'tenant_' . parent::getTenantIdentifierName();
    }
}
