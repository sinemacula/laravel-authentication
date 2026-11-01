<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;

/**
 * Unit tests for a requirement's parts: the maximum ages a part and a level
 * accept, and the shorter of two maximum ages, where none is any age.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementPart::class)]
#[CoversClass(LevelRequirement::class)]
final class RequirementPartTest extends TestCase
{
    /**
     * Rows of `[maximum age]` a part refuses.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideRefusedAges(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
        yield 'over a year' => [RequirementPart::MAX_AGE_SECONDS + 1];
    }

    /**
     * A maximum age outside one second to a year is refused, by a part and by a
     * level alike.
     *
     * @param  int  $age
     * @return void
     */
    #[DataProvider('provideRefusedAges')]
    public function testAMaximumAgeOutsideItsRangeIsRefused(int $age): void
    {
        foreach ([static fn (): object => new RequirementPart($age), static fn (): object => new LevelRequirement(AssuranceLevel::AAL1, $age)] as $make) {
            try {
                $make();

                self::fail('Expected the maximum age to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A requirement\'s maximum age must be between 1 and 31536000 seconds.', $exception->getMessage());
            }
        }
    }

    /**
     * Both ends of the range, and none at all, are accepted and kept.
     *
     * @return void
     */
    public function testAMaximumAgeWithinItsRangeIsKept(): void
    {
        self::assertSame(1, (new RequirementPart(1))->maxAgeSeconds);
        self::assertSame(RequirementPart::MAX_AGE_SECONDS, (new RequirementPart(RequirementPart::MAX_AGE_SECONDS))->maxAgeSeconds);
        self::assertNull((new RequirementPart)->maxAgeSeconds);
        self::assertSame(1, (new LevelRequirement(AssuranceLevel::AAL1, 1))->maxAgeSeconds);
        self::assertSame(AssuranceLevel::AAL2, (new LevelRequirement(AssuranceLevel::AAL2))->level);
        self::assertNull((new LevelRequirement(AssuranceLevel::AAL2))->maxAgeSeconds);
    }

    /**
     * Rows of `[first, second, shorter]`: the shorter of two ages, either one
     * when the other is any age, and any age only when both are.
     *
     * @return iterable<string, array{0: ?int, 1: ?int, 2: ?int}>
     */
    public static function provideAges(): iterable
    {
        yield 'both any age' => [null, null, null];
        yield 'the first any age' => [null, 300, 300];
        yield 'the second any age' => [300, null, 300];
        yield 'the first shorter' => [60, 300, 60];
        yield 'the second shorter' => [300, 60, 60];
        yield 'equal' => [60, 60, 60];
    }

    /**
     * The shorter of two maximum ages.
     *
     * @param  ?int  $first
     * @param  ?int  $second
     * @param  ?int  $shorter
     * @return void
     */
    #[DataProvider('provideAges')]
    public function testTheShorterOfTwoAges(?int $first, ?int $second, ?int $shorter): void
    {
        self::assertSame($shorter, RequirementPart::shorter($first, $second));
    }
}
