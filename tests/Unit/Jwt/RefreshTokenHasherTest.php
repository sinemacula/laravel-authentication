<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;

/**
 * Unit tests for the RefreshTokenHasher rotation-id primitive.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(RefreshTokenHasher::class)]
final class RefreshTokenHasherTest extends TestCase
{
    /**
     * `generate()` returns a non-empty URL-safe string.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGenerateReturnsNonEmptyString(): void
    {
        $first  = RefreshTokenHasher::generate();
        $second = RefreshTokenHasher::generate();

        self::assertNotSame('', $first);
        self::assertNotSame('', $second);
        self::assertNotSame($first, $second, 'Each call should produce a fresh random rotation id.');
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $first);
    }

    /**
     * `hash()` produces a 64-character SHA-256 hex digest.
     *
     * @return void
     */
    public function testHashReturnsSha256HexDigest(): void
    {
        $digest = RefreshTokenHasher::hash('rotation-id');

        self::assertSame(64, strlen($digest));
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $digest);
    }

    /**
     * `verify()` returns true for the matching plaintext / digest pair.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testVerifyAcceptsMatchingPlaintext(): void
    {
        $rotationId = RefreshTokenHasher::generate();
        $digest     = RefreshTokenHasher::hash($rotationId);

        self::assertTrue(RefreshTokenHasher::verify($rotationId, $digest));
    }

    /**
     * `verify()` returns false for a non-matching plaintext / digest pair.
     *
     * @return void
     */
    public function testVerifyRejectsMismatchedPlaintext(): void
    {
        $digest = RefreshTokenHasher::hash('rotation-id');

        self::assertFalse(RefreshTokenHasher::verify('different-rotation-id', $digest));
    }

    /**
     * `verify()` returns false for empty inputs - neither side can
     * meaningfully match an empty string.
     *
     * @return void
     */
    public function testVerifyRejectsEmptyInputs(): void
    {
        self::assertFalse(RefreshTokenHasher::verify('', 'some-digest'));
        self::assertFalse(RefreshTokenHasher::verify('rotation-id', ''));
        self::assertFalse(RefreshTokenHasher::verify('', ''));
    }

    /**
     * The class is intentionally not instantiable - construction is forbidden
     * via the private constructor so consumers cannot accidentally hold a
     * stateful hasher instance. Reflection invokes the private constructor so
     * the line is covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     *
     * @throws \ReflectionException
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(RefreshTokenHasher::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(RefreshTokenHasher::class, $instance);
    }
}
