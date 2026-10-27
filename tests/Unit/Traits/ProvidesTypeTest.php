<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

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
}
