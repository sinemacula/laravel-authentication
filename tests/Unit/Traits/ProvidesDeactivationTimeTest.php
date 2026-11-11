<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ProvidesDeactivationTime;
use Tests\Unit\Stubs\StubDeactivatablePrincipal;

/**
 * Unit tests for the ProvidesDeactivationTime trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ProvidesDeactivationTime::class)]
final class ProvidesDeactivationTimeTest extends TestCase
{
    /**
     * A loaded `deactivated_at` of `null` reads as active.
     *
     * @return void
     */
    public function testANullDeactivationTimeIsActive(): void
    {
        $principal = new StubDeactivatablePrincipal;
        $principal->setAttribute('deactivated_at', null);

        self::assertTrue($principal->isActive());
    }

    /**
     * Rows of deactivation times that are not `null`: past, present, future, as
     * stored text, and text that is no time at all.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function provideDeactivationTimes(): iterable
    {
        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        yield 'a past time' => [$now->subDay()];
        yield 'the present' => [$now];
        yield 'a future time' => [$now->addYear()];
        yield 'a stored time' => ['2026-04-06 12:00:00'];
        yield 'text that is no time' => ['not a time'];
        yield 'an empty string' => [''];
    }

    /**
     * Any deactivation time that is not `null` reads as inactive, whenever it
     * falls, and whether or not it can be read as a time.
     *
     * @param  mixed  $deactivatedAt
     * @return void
     */
    #[DataProvider('provideDeactivationTimes')]
    public function testAnyDeactivationTimeIsInactive(mixed $deactivatedAt): void
    {
        $principal = new StubDeactivatablePrincipal;
        $principal->setAttribute('deactivated_at', $deactivatedAt);

        self::assertFalse($principal->isActive());
    }

    /**
     * Rows of the date casts a deactivation time is commonly given.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideDateCasts(): iterable
    {
        yield 'datetime' => ['datetime'];
        yield 'immutable_datetime' => ['immutable_datetime'];
    }

    /**
     * A date cast on the column changes nothing: the time set through it reads
     * inactive, and clearing it reads active again.
     *
     * @param  string  $cast
     * @return void
     */
    #[DataProvider('provideDateCasts')]
    public function testADateCastChangesNothing(string $cast): void
    {
        $principal = new class extends StubDeactivatablePrincipal {
            /** @var string|null The storage format of the model's dates. */
            protected $dateFormat = 'Y-m-d H:i:s';
        };

        $principal->mergeCasts(['deactivated_at' => $cast]);
        $principal->setAttribute('deactivated_at', CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        self::assertFalse($principal->isActive());

        $principal->setAttribute('deactivated_at', null);

        self::assertTrue($principal->isActive());
    }

    /**
     * A model selected without its deactivation column throws instead of
     * reading as active or inactive.
     *
     * @return void
     */
    public function testIsActiveThrowsWhenTheAttributeIsNotLoaded(): void
    {
        $principal = new StubDeactivatablePrincipal;
        $principal->setAttribute('email', 'partial@example.test');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(
            'Cannot determine whether ' . StubDeactivatablePrincipal::class . ' is active: its `deactivated_at` attribute is not loaded.'
            . ' Select the column or override getDeactivatedAtName().',
        );

        $principal->isActive();
    }

    /**
     * A subclass overriding `getDeactivatedAtName()` remaps the column the
     * trait reads and checks for.
     *
     * @return void
     */
    public function testIsActiveReadsTheOverriddenAttributeName(): void
    {
        $principal = new class extends StubDeactivatablePrincipal {
            /**
             * Column name holding the deactivation time.
             *
             * @return string
             */
            #[\Override]
            protected function getDeactivatedAtName(): string
            {
                return 'suspended_' . parent::getDeactivatedAtName();
            }
        };

        $principal->setAttribute('suspended_deactivated_at', null);
        $principal->setAttribute('deactivated_at', '2026-04-06 12:00:00');

        self::assertTrue($principal->isActive());

        $principal->setAttribute('suspended_deactivated_at', '2026-04-06 12:00:00');
        $principal->setAttribute('deactivated_at', null);

        self::assertFalse($principal->isActive());
    }
}
