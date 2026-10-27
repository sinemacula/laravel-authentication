<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use Tests\Unit\Stubs\StubActiveAwarePrincipal;

/**
 * Unit tests for the ProvidesActiveState trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ProvidesActiveState::class)]
final class ProvidesActiveStateTest extends TestCase
{
    /**
     * The trait casts the loaded `is_active` attribute to bool.
     *
     * @return void
     */
    public function testIsActiveCastsLoadedAttributeToBool(): void
    {
        $active = new StubActiveAwarePrincipal;
        $active->setAttribute('is_active', 1);

        $inactive = new StubActiveAwarePrincipal;
        $inactive->setAttribute('is_active', 0);

        self::assertTrue($active->isActive());
        self::assertFalse($inactive->isActive());
    }

    /**
     * A loaded `null` is a stored value, not a missing column, and reads as
     * inactive.
     *
     * @return void
     */
    public function testIsActiveTreatsLoadedNullAsInactive(): void
    {
        $principal = new StubActiveAwarePrincipal;
        $principal->setAttribute('is_active', null);

        self::assertFalse($principal->isActive());
    }

    /**
     * A model selected without its active column is a misconfiguration: the
     * trait throws rather than reading the missing attribute as active or
     * inactive.
     *
     * @return void
     */
    public function testIsActiveThrowsWhenAttributeIsNotLoaded(): void
    {
        $principal = new StubActiveAwarePrincipal;
        $principal->setAttribute('email', 'partial@example.test');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(
            'Cannot determine whether ' . StubActiveAwarePrincipal::class . ' is active: its `is_active` attribute is not loaded.'
            . ' Select the column or override getActiveAttributeName().',
        );

        $principal->isActive();
    }

    /**
     * A subclass overriding the protected `getActiveAttributeName()` hook, here
     * deriving its column from the parent's, remaps the column the trait reads
     * and checks for.
     *
     * @return void
     */
    public function testIsActiveReadsTheOverriddenAttributeName(): void
    {
        $principal = new class extends StubActiveAwarePrincipal {
            /**
             * Column name holding the active flag.
             *
             * @return string
             */
            #[\Override]
            protected function getActiveAttributeName(): string
            {
                return parent::getActiveAttributeName() . '_override';
            }
        };

        $principal->setAttribute('is_active_override', true);
        $principal->setAttribute('is_active', false);

        self::assertTrue($principal->isActive());
    }
}
