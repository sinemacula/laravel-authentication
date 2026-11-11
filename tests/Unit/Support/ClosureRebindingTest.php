<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Support\ClosureRebinding;
use Tests\Unit\Stubs\ClosureOwnerFixture;

/**
 * Unit tests for moving a replaced object's closures onto its replacement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClosureRebinding::class)]
final class ClosureRebindingTest extends TestCase
{
    /**
     * An anonymous closure bound to the replaced object is bound to the
     * replacement instead.
     *
     * @return void
     */
    public function testAClosureBoundToTheReplacedObjectIsBoundToTheReplacement(): void
    {
        $replaced    = new ClosureOwnerFixture('replaced');
        $replacement = new ClosureOwnerFixture('replacement');

        $rebound = ClosureRebinding::onto($replaced, $replacement, $replaced->closure());

        self::assertSame('replacement', $rebound());
    }

    /**
     * An anonymous closure bound to any other object, an unbound one and a
     * first-class callable of the replaced object are returned as they are.
     *
     * @return void
     */
    public function testAnyOtherClosureIsKeptAsItIs(): void
    {
        $replaced    = new ClosureOwnerFixture('replaced');
        $replacement = new ClosureOwnerFixture('replacement');
        $other       = (new ClosureOwnerFixture('other'))->closure();
        $unbound     = static fn (): string => 'unbound';
        $callable    = $replaced->name(...);

        self::assertSame($other, ClosureRebinding::onto($replaced, $replacement, $other));
        self::assertSame($unbound, ClosureRebinding::onto($replaced, $replacement, $unbound));
        self::assertSame($callable, ClosureRebinding::onto($replaced, $replacement, $callable));
        self::assertSame('replaced', ClosureRebinding::onto($replaced, $replacement, $callable)());
    }

    /**
     * The constructor is private.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ClosureRebinding::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ClosureRebinding::class, $instance);
    }
}
