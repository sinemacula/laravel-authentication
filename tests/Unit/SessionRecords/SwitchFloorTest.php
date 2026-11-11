<?php

declare(strict_types = 1);

namespace Tests\Unit\SessionRecords;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\SessionRecords\SwitchFloor;

/**
 * Unit tests for the floor a context change sets for a session's access tokens.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SwitchFloor::class)]
final class SwitchFloorTest extends TestCase
{
    /**
     * Rows of `[recorded floor offset in seconds from now, or null, expected
     * offset]`.
     *
     * @return iterable<string, array{0: ?int, 1: int}>
     */
    public static function provideFloors(): iterable
    {
        yield 'no change before' => [null, 0];
        yield 'a change in an earlier second' => [-1, 0];
        yield 'a change long ago' => [-3600, 0];
        yield 'a change in this second' => [0, 1];
        yield 'two changes in this second already' => [1, 2];
    }

    /**
     * A change moves the floor past every token from before it, whatever its
     * second.
     *
     * @param  ?int  $recorded
     * @param  int  $expected
     * @return void
     */
    #[DataProvider('provideFloors')]
    public function testTheFloorMovesPastEveryEarlierToken(?int $recorded, int $expected): void
    {
        $now = CarbonImmutable::parse('2026-04-06 12:00:00.750000');

        $floor = SwitchFloor::after($recorded === null ? null : $now->startOfSecond()->addSeconds($recorded), $now);

        self::assertSame($now->startOfSecond()->getTimestamp() + $expected, $floor->getTimestamp());
        self::assertSame(0, (int) $floor->format('u'));
    }

    /**
     * The floor is in the time zone of the change, so it is written as the
     * session's other times are.
     *
     * @return void
     */
    public function testTheFloorKeepsTheChangesTimeZone(): void
    {
        $now = CarbonImmutable::parse('2026-04-06 12:00:00', 'Europe/London');

        self::assertSame('Europe/London', SwitchFloor::after($now, $now)->getTimezone()->getName());
    }

    /**
     * The floor is a utility: it cannot be instantiated from outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SwitchFloor::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(SwitchFloor::class, $instance);
    }
}
