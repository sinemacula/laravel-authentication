<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use Tests\Unit\Stubs\StubTenant;
use Tests\Unit\Traits\Fixtures\Enums\ProvidesTypeTestBackedType;
use Tests\Unit\Traits\Fixtures\Enums\ProvidesTypeTestUnitType;

/**
 * Unit tests for the package ProvidesType trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ProvidesType::class)]
final class ProvidesTypeTest extends TestCase
{
    /**
     * Asserts a `BackedEnum` type attribute resolves to the enum's backing
     * value cast to a string.
     *
     * @return void
     */
    public function testGetTypeReturnsBackedEnumValue(): void
    {
        $tenant = new StubTenant;
        $tenant->setRawAttributes([]);
        $tenant->setAttribute('type', ProvidesTypeTestBackedType::STAFF);

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
        $tenant = new StubTenant;
        $tenant->setRawAttributes([]);
        $tenant->setAttribute('type', ProvidesTypeTestUnitType::CUSTOMER);

        self::assertSame('CUSTOMER', $tenant->getType());
    }

    /**
     * Asserts a plain string type attribute is returned unchanged.
     *
     * @return void
     */
    public function testGetTypeCastsStringToString(): void
    {
        $tenant = new StubTenant;
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
        $tenant = new StubTenant;

        $value = new class implements \Stringable {
            /**
             * To string magic method.
             *
             * @return string
             */
            #[\Override]
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
        $tenant = new StubTenant;
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
        $tenant = new StubTenant;
        $tenant->setRawAttributes(['type' => 1]);

        self::assertSame('1', $tenant->getType());
    }

    /**
     * Asserts the type is read from the column `getTypeAttributeName()` names,
     * so a principal can keep its type in a column of its own choosing.
     *
     * @return void
     */
    public function testGetTypeReadsTheColumnTheAttributeNameHookNames(): void
    {
        $principal = new class extends Model implements HasType {
            use ProvidesType;

            /**
             * Column name holding the type.
             *
             * @return string
             */
            protected function getTypeAttributeName(): string
            {
                return 'role';
            }
        };

        $principal->setRawAttributes(['type' => 'ignored', 'role' => 'client_admin']);

        self::assertSame('client_admin', $principal->getType());
    }

    /**
     * Asserts a model loaded without its type attribute throws instead of
     * reporting no type, which would hand a principal its tenant's type.
     *
     * @return void
     */
    public function testGetTypeThrowsWhenTheAttributeIsNotLoaded(): void
    {
        $tenant = new StubTenant;
        $tenant->setRawAttributes(['id' => 1]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(
            'Cannot read the type of ' . StubTenant::class . ': its `type` attribute is not loaded. Select the column or override getTypeAttributeName().',
        );

        $tenant->getType();
    }

    /**
     * Asserts the check follows the attribute `getTypeAttributeName()` names,
     * so a model with that one loaded reads it although it has no `type`.
     *
     * @return void
     */
    public function testGetTypeChecksTheAttributeTheNameHookNames(): void
    {
        $principal = new class extends Model implements HasType {
            use ProvidesType;

            /**
             * Column name holding the type.
             *
             * @return string
             */
            protected function getTypeAttributeName(): string
            {
                return 'role';
            }
        };

        $principal->setRawAttributes(['role' => null]);

        self::assertSame('', $principal->getType());

        $principal->setRawAttributes(['type' => 'staff']);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `role` attribute is not loaded');

        $principal->getType();
    }

    /**
     * Asserts a type computed by an accessor is read although no column of that
     * name was loaded.
     *
     * @return void
     */
    public function testGetTypeReadsAnAccessorWithoutAColumn(): void
    {
        $principal = new class extends Model implements HasType {
            use ProvidesType;

            /**
             * The type, derived rather than stored.
             *
             * @return \Illuminate\Database\Eloquent\Casts\Attribute<string, never>
             */
            protected function type(): Attribute
            {
                return Attribute::get(static fn (): string => 'derived');
            }
        };

        $principal->setRawAttributes(['role' => 'admin']);

        self::assertSame('derived', $principal->getType());
    }
}
