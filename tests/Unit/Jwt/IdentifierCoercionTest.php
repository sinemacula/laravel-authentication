<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Unit tests for the `IdentifierCoercion` JWT claim helper.
 *
 * Pins the documented branch matrix:
 *
 * - `null` -> `null` - `string` -> the same string verbatim -
 * `int`/`float`/`bool`-> `(string)` cast - `Stringable` object ->
 * `__toString()` - any other type -> `null` (fail-closed; no `sub` claim)
 *
 * Each branch is asserted from a separate row so a mutation that collapses two
 * arms into one is killed independently.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(IdentifierCoercion::class)]
final class IdentifierCoercionTest extends TestCase
{
    /**
     * Asserts `null` input returns `null` so callers can omit the claim
     * entirely rather than embedding the literal string `'null'`.
     *
     * @return void
     */
    public function testStringifyReturnsNullForNull(): void
    {
        self::assertNull(IdentifierCoercion::stringify(null));
    }

    /**
     * Asserts a string input is returned verbatim - no normalisation,
     * trimming, or case folding - so the round-trip with the resolver is
     * byte-identical.
     *
     * @return void
     */
    public function testStringifyReturnsStringVerbatim(): void
    {
        self::assertSame('user-42', IdentifierCoercion::stringify('user-42'));
    }

    /**
     * Asserts an empty string is returned verbatim - the helper does not
     * normalise empty input to `null`, leaving caller policy in charge of
     * rejecting empty subjects.
     *
     * @return void
     */
    public function testStringifyReturnsEmptyStringVerbatim(): void
    {
        self::assertSame('', IdentifierCoercion::stringify(''));
    }

    /**
     * Asserts an integer auto-increment id is cast to its decimal string form.
     *
     * @return void
     */
    public function testStringifyCastsIntegerToString(): void
    {
        self::assertSame('42', IdentifierCoercion::stringify(42));
    }

    /**
     * Asserts the literal `0` integer is cast to `'0'` and NOT collapsed to
     * `null` - protects against a mutation that swaps the type check for a
     * truthy check.
     *
     * @return void
     */
    public function testStringifyCastsZeroIntegerToZeroString(): void
    {
        self::assertSame('0', IdentifierCoercion::stringify(0));
    }

    /**
     * Asserts a float identifier is cast to its string form.
     *
     * @return void
     */
    public function testStringifyCastsFloatToString(): void
    {
        self::assertSame('1.5', IdentifierCoercion::stringify(1.5));
    }

    /**
     * Asserts a boolean `true` is cast to the string `'1'` (PHP's native
     * bool->string convention).
     *
     * @return void
     */
    public function testStringifyCastsTrueToOneString(): void
    {
        self::assertSame('1', IdentifierCoercion::stringify(true));
    }

    /**
     * Asserts a boolean `false` is cast to the empty string (PHP's native
     * bool->string convention) - again documenting that the helper does not
     * collapse `false` to `null`.
     *
     * @return void
     */
    public function testStringifyCastsFalseToEmptyString(): void
    {
        self::assertSame('', IdentifierCoercion::stringify(false));
    }

    /**
     * Asserts a `Stringable` object is coerced via `__toString()`.
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
            public function __toString(): string
            {
                return 'stringable-id';
            }
        };

        self::assertSame('stringable-id', IdentifierCoercion::stringify($value));
    }

    /**
     * Asserts an arbitrary array input is rejected with `null` - arrays do not
     * satisfy the JWT `StringOrURI` claim form.
     *
     * @return void
     */
    public function testStringifyReturnsNullForArray(): void
    {
        self::assertNull(IdentifierCoercion::stringify([1, 2, 3]));
    }

    /**
     * Asserts an arbitrary `\stdClass` (non-Stringable) object is rejected
     * with `null` so a misbehaving custom resolver cannot embed an object
     * literal in the `sub` claim.
     *
     * @return void
     */
    public function testStringifyReturnsNullForArbitraryObject(): void
    {
        self::assertNull(IdentifierCoercion::stringify(new \stdClass));
    }

    /**
     * Asserts an open file resource is rejected with `null`.
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
     * The class is intentionally not instantiable - construction is forbidden
     * via the private constructor so consumers cannot create a stateful
     * coercion helper. Reflection is used to invoke the private constructor so
     * the line is covered while still documenting the access modifier.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(IdentifierCoercion::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();    // NOSONAR
        $constructor->invoke($instance);    // NOSONAR

        self::assertInstanceOf(IdentifierCoercion::class, $instance);
    }
}
