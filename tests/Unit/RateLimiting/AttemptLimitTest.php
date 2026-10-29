<?php

declare(strict_types = 1);

namespace Tests\Unit\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptLimit;

/**
 * Unit tests for one attempt limit and its clock-aligned windows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptLimit::class)]
final class AttemptLimitTest extends TestCase
{
    /**
     * Rows of `[max, decay seconds, accepted]` at and beyond each bound.
     *
     * @return iterable<string, array{0: int, 1: int, 2: bool}>
     */
    public static function provideBounds(): iterable
    {
        yield from [
            'no attempts'       => [0, 60, false],
            'negative attempts' => [-1, 60, false],
            'one attempt'       => [1, 60, true],
            'no window'         => [5, 0, false],
            'one-second window' => [5, 1, true],
            'one-day window'    => [5, 86400, true],
            'longer than a day' => [5, 86401, false],
        ];
    }

    /**
     * A limit allows at least one attempt in a window of one second to a day.
     *
     * @param  int  $max
     * @param  int  $decay
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideBounds')]
    public function testAcceptsExactlyItsBounds(int $max, int $decay, bool $accepted): void
    {
        if (!$accepted) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage("A limit needs at least 1 attempt in a window of 1 to 86400 seconds, {$max} in {$decay} given.");
        }

        $limit = new AttemptLimit($max, $decay);

        self::assertSame([$max, $decay], [$limit->max, $limit->decaySeconds]);
    }

    /**
     * Rows of `[decay seconds, now, window end]`.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int}>
     */
    public static function provideWindows(): iterable
    {
        yield from [
            'start of a window'       => [300, 1800000000, 1800000300],
            'inside a window'         => [300, 1800000123, 1800000300],
            'last second of a window' => [300, 1800000299, 1800000300],
            'one-second windows'      => [1, 1800000123, 1800000124],
            'day-long windows'        => [86400, 1800000123, 1800057600],
        ];
    }

    /**
     * Windows are aligned to the clock: the end is the first multiple of the
     * window length after now, whenever the first attempt came.
     *
     * @param  int  $decay
     * @param  int  $now
     * @param  int  $end
     * @return void
     */
    #[DataProvider('provideWindows')]
    public function testWindowsAreAlignedToTheClock(int $decay, int $now, int $end): void
    {
        self::assertSame($end, (new AttemptLimit(5, $decay))->windowEnd($now));
    }
}
