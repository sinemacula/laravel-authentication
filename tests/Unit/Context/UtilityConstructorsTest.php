<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Context\ContextBuilder;
use SineMacula\Laravel\Authentication\Context\ContextForgetting;
use SineMacula\Laravel\Authentication\Context\ContextKeys;

/**
 * The context utility classes cannot be instantiated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextBuilder::class)]
#[CoversClass(ContextForgetting::class)]
#[CoversClass(ContextKeys::class)]
final class UtilityConstructorsTest extends TestCase
{
    /**
     * Rows of `[class]`: the utility classes.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideUtilities(): iterable
    {
        yield from [
            'builder'    => [ContextBuilder::class],
            'forgetting' => [ContextForgetting::class],
            'keys'       => [ContextKeys::class],
        ];
    }

    /**
     * The constructor is private.
     *
     * @param  class-string  $class
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    #[DataProvider('provideUtilities')]
    public function testConstructorIsPrivate(string $class): void
    {
        $reflection  = new \ReflectionClass($class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf($class, $instance);
    }
}
