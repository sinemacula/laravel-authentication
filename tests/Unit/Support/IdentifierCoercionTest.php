<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Unit tests for the `IdentifierCoercion` JWT claim helper.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierCoercion::class)]
final class IdentifierCoercionTest extends TestCase
{
    /**
     * A `null` identifier is returned as `null`.
     *
     * @return void
     */
    public function testStringifyReturnsNullForNull(): void
    {
        self::assertNull(IdentifierCoercion::stringify(null));
    }

    /**
     * A string is returned verbatim.
     *
     * @return void
     */
    public function testStringifyReturnsStringVerbatim(): void
    {
        self::assertSame('user-42', IdentifierCoercion::stringify('user-42'));
    }

    /**
     * An empty string is returned verbatim, not as `null`.
     *
     * @return void
     */
    public function testStringifyReturnsEmptyStringVerbatim(): void
    {
        self::assertSame('', IdentifierCoercion::stringify(''));
    }

    /**
     * An integer is cast to its decimal string.
     *
     * @return void
     */
    public function testStringifyCastsIntegerToString(): void
    {
        self::assertSame('42', IdentifierCoercion::stringify(42));
    }

    /**
     * The integer `0` is cast to `'0'`, not `null`.
     *
     * @return void
     */
    public function testStringifyCastsZeroIntegerToZeroString(): void
    {
        self::assertSame('0', IdentifierCoercion::stringify(0));
    }

    /**
     * A float is cast to its string form.
     *
     * @return void
     */
    public function testStringifyCastsFloatToString(): void
    {
        self::assertSame('1.5', IdentifierCoercion::stringify(1.5));
    }

    /**
     * A boolean `true` is cast to `'1'`.
     *
     * @return void
     */
    public function testStringifyCastsTrueToOneString(): void
    {
        self::assertSame('1', IdentifierCoercion::stringify(true));
    }

    /**
     * A boolean `false` is cast to the empty string, not `null`.
     *
     * @return void
     */
    public function testStringifyCastsFalseToEmptyString(): void
    {
        self::assertSame('', IdentifierCoercion::stringify(false));
    }

    /**
     * A `Stringable` object is cast via `__toString()`.
     *
     * @return void
     */
    public function testStringifyCastsStringableToStringViaMagicMethod(): void
    {
        $value = new class implements \Stringable {
            /**
             * Stringable contract.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'stringable-id';
            }
        };

        self::assertSame('stringable-id', IdentifierCoercion::stringify($value));
    }

    /**
     * An array is rejected with `null`.
     *
     * @return void
     */
    public function testStringifyReturnsNullForArray(): void
    {
        self::assertNull(IdentifierCoercion::stringify([1, 2, 3]));
    }

    /**
     * A non-Stringable object is rejected with `null`.
     *
     * @return void
     */
    public function testStringifyReturnsNullForArbitraryObject(): void
    {
        self::assertNull(IdentifierCoercion::stringify(new \stdClass));
    }

    /**
     * An open file resource is rejected with `null`.
     *
     * @return void
     */
    public function testStringifyReturnsNullForResource(): void
    {
        $resource = fopen('php://memory', 'rb');

        self::assertIsResource($resource);

        try {
            self::assertNull(IdentifierCoercion::stringify($resource));
        } finally {
            fclose($resource);
        }
    }

    /**
     * An identifier matches a supplied value with the same string form, so an
     * integer key matches its decimal string as it arrives in a claim.
     *
     * @return void
     */
    public function testMatchesComparesTheStringForms(): void
    {
        self::assertTrue(IdentifierCoercion::matches('p-1', 'p-1'));
        self::assertTrue(IdentifierCoercion::matches(5, '5'));
        self::assertTrue(IdentifierCoercion::matches('5', 5));
        self::assertFalse(IdentifierCoercion::matches('p-1', 'p-2'));
        self::assertFalse(IdentifierCoercion::matches('p-1', 'p-10'));
    }

    /**
     * Matching fails closed when either side does not coerce, including two
     * `null` identifiers, so an unsaved model never matches a missing hint.
     *
     * @return void
     */
    public function testMatchesFailsClosedWhenEitherSideDoesNotCoerce(): void
    {
        self::assertFalse(IdentifierCoercion::matches(null, 'p-1'));
        self::assertFalse(IdentifierCoercion::matches('p-1', null));
        self::assertFalse(IdentifierCoercion::matches(null, null));
        self::assertFalse(IdentifierCoercion::matches([1], [1]));
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
        $reflection  = new \ReflectionClass(IdentifierCoercion::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(IdentifierCoercion::class, $instance);
    }
}
