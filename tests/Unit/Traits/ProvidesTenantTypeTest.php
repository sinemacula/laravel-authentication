<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\ProvidesTenantType;
use Tests\Unit\Traits\Fixtures\ProvidesTenantTypeTestBackedType;
use Tests\Unit\Traits\Fixtures\ProvidesTenantTypeTestUnitType;

/**
 * Unit tests for the package ProvidesTenantType trait.
 *
 * Both `#[CoversTrait]` and `#[CoversMethod]` are present so PHPUnit
 * attributes the trait's coverage correctly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversMethod(ProvidesTenantType::class, 'getType')]
#[CoversTrait(ProvidesTenantType::class)]
final class ProvidesTenantTypeTest extends TestCase
{
    /**
     * Asserts a `BackedEnum` type attribute resolves to the enum's backing
     * value cast to a string.
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
        $tenant->setAttribute('type', ProvidesTenantTypeTestBackedType::STAFF);

        self::assertSame('staff', $tenant->getType());
    }

    /**
     * Asserts a non-backed `UnitEnum` type attribute resolves to the enum case
     * name.
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
        $tenant->setAttribute('type', ProvidesTenantTypeTestUnitType::CUSTOMER);

        self::assertSame('CUSTOMER', $tenant->getType());
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
             * To string magic method.
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

    /**
     * Asserts a `null` type attribute is cast to the empty string via the
     * `(string)` fallback - not returned as `null`. Pins the documented
     * `(string) null === ''` boundary.
     *
     * @return void
     */
    public function testGetTypeCastsNullToEmptyString(): void
    {
        $tenant = new class extends Model {
            use ProvidesTenantType;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $tenant->setRawAttributes(['type' => null]);

        self::assertSame('', $tenant->getType());
    }

    /**
     * Asserts an integer type attribute is cast to its string form via the
     * `(string)` fallback (e.g. `1` becomes `'1'`).
     *
     * @return void
     */
    public function testGetTypeCastsIntegerToString(): void
    {
        $tenant = new class extends Model {
            use ProvidesTenantType;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $tenant->setRawAttributes(['type' => 1]);

        self::assertSame('1', $tenant->getType());
    }
}
