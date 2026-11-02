<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;

/**
 * Unit tests for the default tenant resolver, which resolves no identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolveNoTenant::class)]
final class ResolveNoTenantTest extends TestCase
{
    /**
     * No identifier names a tenant, whatever it looks like.
     *
     * @return void
     */
    public function testResolvesNoTenant(): void
    {
        $resolver = new ResolveNoTenant;

        foreach (['1', 'tenant-a', '0198f2a4-9c1e-7d55-a3b2-6f0e3d1c2b4a'] as $tenantId) {
            self::assertNull($resolver->resolve($tenantId));
        }
    }
}
