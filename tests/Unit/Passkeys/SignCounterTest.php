<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\SignCounter;

/**
 * Unit tests for the sign counter rule: an assertion is accepted when its count
 * is above the stored one, or when both are 0 (an authenticator without a
 * counter); anything else is a regression.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignCounter::class)]
final class SignCounterTest extends TestCase
{
    /**
     * Rows of `[stored, presented, accepted]`.
     *
     * @return iterable<string, array{0: int, 1: int, 2: bool}>
     */
    public static function provideCounts(): iterable
    {
        yield from [
            'no counter on either side'             => [0, 0, true],
            'a first count after none'              => [0, 1, true],
            'a count that jumps forward'            => [0, 5, true],
            'the next count'                        => [5, 6, true],
            'the highest count after the one below' => [4294967294, 4294967295, true],
            'the same count again'                  => [5, 5, false],
            'a count that goes back'                => [5, 4, false],
            'a counter that drops to none'          => [5, 0, false],
            'the first count repeated'              => [1, 1, false],
            'none after the highest count'          => [4294967295, 0, false],
        ];
    }

    /**
     * Each pair of counts is accepted or refused as the rule says.
     *
     * @param  int  $stored
     * @param  int  $presented
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideCounts')]
    public function testTheRuleAcceptsOnlyAnAdvancingCountOrNoCounterAtAll(int $stored, int $presented, bool $accepted): void
    {
        self::assertSame($accepted, SignCounter::accepts($stored, $presented));
    }

    /**
     * `SignCounter` is a static utility; instantiation is disallowed via the
     * private constructor. Reflection invokes the private constructor so the
     * line is covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SignCounter::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(SignCounter::class, $instance);
    }
}
