<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\ActsAsOrganization;
use Tests\Unit\Traits\Fixtures\ActsAsOrganizationTestBackedScope;
use Tests\Unit\Traits\Fixtures\ActsAsOrganizationTestUnitScope;

/**
 * Unit tests for the package ActsAsOrganization trait.
 *
 * Marked `#[CoversNothing]` so phpunit does not attribute the
 * trait's runtime behaviour to a single concrete class — the
 * trait's real consumers carry their own coverage via the
 * integration suites.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class ActsAsOrganizationTest extends TestCase
{
    /**
     * Asserts the organization identifier getter reads the model's
     * `id` attribute when no attribute-name override is supplied.
     *
     * @return void
     */
    public function testGetOrganizationIdentifierReturnsIdAttribute(): void
    {
        $organization = new class extends Model {
            use ActsAsOrganization;

            /** @var bool Indicates whether the IDs are auto-incrementing. */
            public $incrementing = false;

            /** @var string The "type" of the primary key ID. */
            protected $keyType = 'string';

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $organization->setRawAttributes(['id' => 'org-123']);

        self::assertSame('org-123', $organization->getOrganizationIdentifier());
    }

    /**
     * Asserts a `BackedEnum` scope attribute resolves to the enum's
     * backing value cast to a string.
     *
     * @return void
     */
    public function testGetOrganizationScopeReturnsBackedEnumValue(): void
    {
        $organization = new class extends Model {
            use ActsAsOrganization;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $organization->setRawAttributes([]);
        $organization->setAttribute('scope', ActsAsOrganizationTestBackedScope::Internal);

        self::assertSame('internal', $organization->getOrganizationScope());
    }

    /**
     * Asserts a non-backed `UnitEnum` scope attribute resolves to the
     * enum case name.
     *
     * @return void
     */
    public function testGetOrganizationScopeReturnsUnitEnumName(): void
    {
        $organization = new class extends Model {
            use ActsAsOrganization;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $organization->setRawAttributes([]);
        $organization->setAttribute('scope', ActsAsOrganizationTestUnitScope::External);

        self::assertSame('External', $organization->getOrganizationScope());
    }

    /**
     * Asserts a plain string scope attribute is returned unchanged.
     *
     * @return void
     */
    public function testGetOrganizationScopeCastsStringToString(): void
    {
        $organization = new class extends Model {
            use ActsAsOrganization;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $organization->setRawAttributes(['scope' => 'customer']);

        self::assertSame('customer', $organization->getOrganizationScope());
    }

    /**
     * Asserts a `Stringable` scope attribute is coerced to its string
     * representation via the `(string)` cast.
     *
     * @return void
     */
    public function testGetOrganizationScopeCastsObjectViaStringConversion(): void
    {
        $organization = new class extends Model {
            use ActsAsOrganization;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $scope = new class implements \Stringable {
            /**
             * __Tostring.
             *
             * @return string
             */
            public function __toString(): string
            {
                return 'stringable-scope';
            }
        };

        $organization->setRawAttributes([]);
        $organization->setAttribute('scope', $scope);

        self::assertSame('stringable-scope', $organization->getOrganizationScope());
    }
}
