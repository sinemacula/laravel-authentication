<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;

/**
 * Unit tests for the assurance levels: the values a further-factor package
 * reports them with, and their order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssuranceLevel::class)]
final class AssuranceLevelTest extends TestCase
{
    /**
     * The levels carry the shared values, lowest first.
     *
     * @return void
     */
    public function testTheLevelsCarryTheSharedValues(): void
    {
        self::assertSame(['aal1', 'aal2', 'aal3'], array_map(static fn (AssuranceLevel $level): string => $level->value, AssuranceLevel::cases()));
    }

    /**
     * Rows of `[level, asked, at least]` over every pair of levels.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel, 1: \SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel, 2: bool}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideLevels(): iterable
    {
        foreach (AssuranceLevel::cases() as $rank => $level) {
            foreach (AssuranceLevel::cases() as $askedRank => $asked) {
                yield "{$level->value} against {$asked->value}" => [$level, $asked, $rank >= $askedRank];
            }
        }
    }

    /**
     * A level is at least itself and every lower level, and never a higher one.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel  $level
     * @param  \SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel  $asked
     * @param  bool  $atLeast
     * @return void
     */
    #[DataProvider('provideLevels')]
    public function testALevelIsAtLeastTheLevelsBelowIt(AssuranceLevel $level, AssuranceLevel $asked, bool $atLeast): void
    {
        self::assertSame($atLeast, $level->isAtLeast($asked));
    }
}
