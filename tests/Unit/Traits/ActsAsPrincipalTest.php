<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

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
#[\PHPUnit\Framework\Attributes\CoversNothing]
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
        $principal = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };
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

        $principal = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };
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
        $principal = new class extends Model implements Identity {
            use ActsAsPrincipal, Authenticatable;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        self::assertSame($principal, $principal->getIdentity());
    }

    /**
     * Trait throws LogicException when the identity relation is absent.
     *
     * @return void
     */
    public function testGetIdentityThrowsLogicExceptionWhenRelationMissing(): void
    {
        $principal = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };
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

        $principal = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];

            /**
             * Override the identity relation name.
             *
             * @return string
             */
            protected function getIdentityRelationName(): string
            {
                return 'owner';
            }
        };
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

        $principal = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };
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
        $principal = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };
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
        $active = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $active->setAttribute('is_active', 1);

        $inactive = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $inactive->setAttribute('is_active', 0);

        self::assertTrue($active->isActive());
        self::assertFalse($inactive->isActive());
    }
}
