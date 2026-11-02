<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;
use Tests\Unit\Stubs\StubTenant;

/**
 * Unit tests for the default tenant access (D18): a principal may act only in
 * its own tenant, by class and identifier, and a platform principal only in
 * none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnTenantOnly::class)]
final class OwnTenantOnlyTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A principal may act in its own tenant, matched by identifier whatever its
     * type (an integer key against its string form), and not in none.
     *
     * @return void
     */
    public function testAPrincipalMayActInItsOwnTenantOnly(): void
    {
        $access    = new OwnTenantOnly;
        $principal = new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7));

        self::assertTrue($access->mayActIn($principal, new PlainTenantFixture(7)));
        self::assertTrue($access->mayActIn($principal, new PlainTenantFixture('7')));
        self::assertFalse($access->mayActIn($principal, new PlainTenantFixture(8)));
        self::assertFalse($access->mayActIn($principal, null));
    }

    /**
     * A tenant of another class with the same identifier is not the principal's
     * own.
     *
     * @return void
     */
    public function testATenantOfAnotherClassIsNotItsOwn(): void
    {
        $other = (new StubTenant)->forceFill(['id' => 7]);

        self::assertFalse((new OwnTenantOnly)->mayActIn(new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7)), $other));
    }

    /**
     * A platform principal may act in no tenant, and in none other.
     *
     * @return void
     */
    public function testAPlatformPrincipalMayActOnlyInNone(): void
    {
        $access    = new OwnTenantOnly;
        $principal = new PlainPrincipalFixture(1);

        self::assertTrue($access->mayActIn($principal, null));
        self::assertFalse($access->mayActIn($principal, new PlainTenantFixture(7)));
    }

    /**
     * A principal whose own tenant cannot be loaded may act nowhere, not even
     * in a tenant with that tenant's identifier, nor in none.
     *
     * @return void
     */
    public function testAPrincipalWhoseTenantCannotBeLoadedMayActNowhere(): void
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->andThrow(new TenantUnavailableException('The tenant is gone.'));

        self::assertFalse((new OwnTenantOnly)->mayActIn($principal, new PlainTenantFixture(7)));
        self::assertFalse((new OwnTenantOnly)->mayActIn($principal, null));
    }
}
