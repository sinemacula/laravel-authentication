<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
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
     * Overriding `getActiveAttributeName()` remaps the column the trait reads
     * and checks for.
     *
     * @return void
     */
    public function testIsActiveReadsTheOverriddenAttributeName(): void
    {
        $model = new class extends Model implements CanBeActive {
            use ProvidesActiveState;

            /** @var array<string> The attributes that aren't mass assignable. */
            protected $guarded = [];

            /**
             * Column name holding the active flag.
             *
             * @return string
             */
            protected function getActiveAttributeName(): string
            {
                return 'enabled';
            }
        };

        $model->setAttribute('enabled', true);
        $model->setAttribute('is_active', false);

        self::assertTrue($model->isActive());
    }
}
