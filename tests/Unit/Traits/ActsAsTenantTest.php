<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\ActsAsTenant;
use Tests\Unit\Stubs\StubTenant;
use Tests\Unit\Stubs\StubTenantWithCustomIdentifier;

/**
 * Unit tests for the package ActsAsTenant trait.
 *
 * Exercises the public trait surface through named Eloquent stubs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ActsAsTenant::class)]
final class ActsAsTenantTest extends TestCase
{
    /**
     * Asserts the tenant identifier getter reads the model's `id` attribute
     * when no attribute-name override is supplied.
     *
     * @return void
     */
    public function testGetTenantIdentifierReturnsIdAttribute(): void
    {
        $tenant = new StubTenant;
        $tenant->setRawAttributes(['id' => 123]);

        self::assertSame(123, $tenant->getTenantIdentifier());
    }

    /**
     * Asserts a subclass override of the protected `getTenantIdentifierName()`
     * hook is honoured by the public `getTenantIdentifier()` getter.
     *
     * @return void
     */
    public function testGetTenantIdentifierHonoursAttributeNameOverride(): void
    {
        $tenant = new StubTenantWithCustomIdentifier;
        $tenant->setRawAttributes(['tenant_uuid' => 'tenant-from-override']);

        self::assertSame('tenant-from-override', $tenant->getTenantIdentifier());
    }
}
