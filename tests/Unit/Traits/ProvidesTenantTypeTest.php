<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\ProvidesTenantType;
use Tests\Unit\Traits\Fixtures\ProvidesTenantTypeTestBackedType;
use Tests\Unit\Traits\Fixtures\ProvidesTenantTypeTestUnitType;

/**
 * Unit tests for the package ProvidesTenantType trait.
 *
 * Marked `#[CoversNothing]` so phpunit does not attribute the
 * trait's runtime behaviour to a single concrete class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class ProvidesTenantTypeTest extends TestCase
{
    /**
     * Asserts a `BackedEnum` type attribute resolves to the enum's
     * backing value cast to a string.
     *
     * @return void
     */
    public function testGetTypeReturnsBackedEnumValue(): void
    {
        $tenant = new class extends Model {
            use ProvidesTenantType;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $tenant->setRawAttributes([]);
        $tenant->setAttribute('type', ProvidesTenantTypeTestBackedType::Staff);

        self::assertSame('staff', $tenant->getType());
    }

    /**
     * Asserts a non-backed `UnitEnum` type attribute resolves to the
     * enum case name.
     *
     * @return void
     */
    public function testGetTypeReturnsUnitEnumName(): void
    {
        $tenant = new class extends Model {
            use ProvidesTenantType;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $tenant->setRawAttributes([]);
        $tenant->setAttribute('type', ProvidesTenantTypeTestUnitType::Customer);

        self::assertSame('Customer', $tenant->getType());
    }

    /**
     * Asserts a plain string type attribute is returned unchanged.
     *
     * @return void
     */
    public function testGetTypeCastsStringToString(): void
    {
        $tenant = new class extends Model {
            use ProvidesTenantType;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $tenant->setRawAttributes(['type' => 'customer']);

        self::assertSame('customer', $tenant->getType());
    }

    /**
     * Asserts a `Stringable` type attribute is coerced to its string
     * representation via the `(string)` cast.
     *
     * @return void
     */
    public function testGetTypeCastsObjectViaStringConversion(): void
    {
        $tenant = new class extends Model {
            use ProvidesTenantType;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $value = new class implements \Stringable {
            /**
             * __Tostring.
             *
             * @return string
             */
            public function __toString(): string
            {
                return 'stringable-type';
            }
        };

        $tenant->setRawAttributes([]);
        $tenant->setAttribute('type', $value);

        self::assertSame('stringable-type', $tenant->getType());
    }
}
