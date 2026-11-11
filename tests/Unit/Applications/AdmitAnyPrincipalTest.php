<?php

declare(strict_types = 1);

namespace Tests\Unit\Applications;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Unit tests for the default application access: any principal may use any
 * application (D18).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdmitAnyPrincipal::class)]
final class AdmitAnyPrincipalTest extends TestCase
{
    /**
     * Any principal, active or not, may use every application.
     *
     * @return void
     */
    public function testAnyPrincipalMayUseAnyApplication(): void
    {
        $access = new AdmitAnyPrincipal;

        foreach (['admin', 'console', 'mobile'] as $application) {
            self::assertTrue($access->mayUse($application, new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7))));
            self::assertTrue($access->mayUse($application, new PlainPrincipalFixture(2)));
            self::assertTrue($access->mayUse($application, new PlainPrincipalFixture(3, active: false)));
        }
    }
}
