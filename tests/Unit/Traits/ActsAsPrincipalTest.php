<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use Tests\Unit\Stubs\Stub3dPrincipal;
use Tests\Unit\Stubs\Stub3dPrincipalWithOwnerRelation;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Unit tests for the ActsAsPrincipal trait.
 *
 * Exercises the public trait surface without relying on explicit PHPUnit
 * coverage metadata for traits.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ActsAsPrincipalTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Trait returns the configured id attribute as the principal identifier.
     *
     * @return void
     */
    public function testGetPrincipalIdentifierReturnsIdAttribute(): void
    {
        $principal = new Stub3dPrincipal;
        $principal->setAttribute('id', 42);

        self::assertSame(42, $principal->getPrincipalIdentifier());
    }

    /**
     * Trait returns the identity relation when it implements Identity.
     *
     * @return void
     */
    public function testGetIdentityReturnsRelatedIdentity(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $principal = new Stub3dPrincipal;
        $principal->setRelation('identity', $identity);

        self::assertSame($identity, $principal->getIdentity());
    }

    /**
     * Trait short-circuits to the principal itself when the model implements
     * `Identity` (2D mode), so the `identity` relation is never queried.
     *
     * @return void
     */
    public function testGetIdentityReturnsSelfWhen2dIdentity(): void
    {
        $principal = new StubPrincipal;

        self::assertSame($principal, $principal->getIdentity());
    }

    /**
     * Trait throws LogicException when the identity relation is absent.
     *
     * @return void
     */
    public function testGetIdentityThrowsLogicExceptionWhenRelationMissing(): void
    {
        $principal = new Stub3dPrincipal;
        $principal->setRelation('identity', null);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('expected its identity relation `identity` to return an Identity instance');

        $principal->getIdentity();
    }

    /**
     * Trait honours an `identityRelationName` override declared on the
     * principal subclass and reads the identity from the renamed relation slot.
     *
     * @return void
     */
    public function testGetIdentityHonoursIdentityRelationNameOverride(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $principal = new Stub3dPrincipalWithOwnerRelation;
        $principal->setRelation('owner', $identity);

        self::assertSame($identity, $principal->getIdentity());
    }

    /**
     * Trait returns the tenant relation when it implements Tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsRelatedTenant(): void
    {
        $tenant = \Mockery::mock(Tenant::class);

        $principal = new Stub3dPrincipal;
        $principal->setRelation('tenant', $tenant);

        self::assertSame($tenant, $principal->getTenant());
    }

    /**
     * Trait returns null when the tenant relation is absent.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenAbsent(): void
    {
        $principal = new Stub3dPrincipal;
        $principal->setRelation('tenant', null);

        self::assertNull($principal->getTenant());
    }

    /**
     * Trait casts the is_active attribute to bool.
     *
     * @return void
     */
    public function testIsActiveCastsAttributeToBool(): void
    {
        $active = new Stub3dPrincipal;
        $active->setAttribute('is_active', 1);

        $inactive = new Stub3dPrincipal;
        $inactive->setAttribute('is_active', 0);

        self::assertTrue($active->isActive());
        self::assertFalse($inactive->isActive());
    }
}
