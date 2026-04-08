<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use LogicException;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;

/**
 * Unit tests for the ActsAsPrincipal trait.
 *
 * Marked `#[CoversNothing]` so phpunit does not attribute the
 * trait's runtime behaviour to a single concrete class - the
 * trait's real consumers carry their own coverage via the
 * integration suites.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[CoversNothing]
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
     * Trait returns the organization relation when it implements Organization.
     *
     * @return void
     */
    public function testGetOrganizationReturnsRelatedOrganization(): void
    {
        $organization = \Mockery::mock(Organization::class);

        $principal = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };
        $principal->setRelation('organization', $organization);

        self::assertSame($organization, $principal->getOrganization());
    }

    /**
     * Trait returns null when the organization relation is absent.
     *
     * @return void
     */
    public function testGetOrganizationReturnsNullWhenAbsent(): void
    {
        $principal = new class extends Model {
            use ActsAsPrincipal;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };
        $principal->setRelation('organization', null);

        self::assertNull($principal->getOrganization());
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
