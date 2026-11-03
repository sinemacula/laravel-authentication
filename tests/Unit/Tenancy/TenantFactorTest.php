<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\TenantFactor;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Unit tests for a tenant's further-factor requirement held with its tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantFactor::class)]
final class TenantFactorTest extends TestCase
{
    /**
     * It keeps the tenant and the requirement as given.
     *
     * @return void
     */
    public function testItKeepsTheTenantAndItsRequirement(): void
    {
        $tenant      = new PlainTenantFixture(3);
        $requirement = new Requirement(multifactor: new RequirementPart(300));
        $factor      = new TenantFactor($tenant, $requirement);

        self::assertSame([$tenant, $requirement], [$factor->tenant, $factor->requirement]);
    }
}
