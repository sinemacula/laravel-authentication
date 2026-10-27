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
 * @copyright   2026 Sine Macula Limited
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
     * `verify()` returns false for empty inputs - neither side can meaningfully
     * match an empty string.
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
     * `successor()` derives the next rotation id deterministically: the same id
     * always has the same successor, which is shaped like a generated id (43
     * URL-safe characters) and differs from the id and from its digest.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSuccessorIsADeterministicRotationIdOfTheSameShape(): void
    {
        $rotationId = RefreshTokenHasher::generate();
        $successor  = RefreshTokenHasher::successor($rotationId);

        self::assertSame($successor, RefreshTokenHasher::successor($rotationId));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $successor);
        self::assertSame(strlen($rotationId), strlen($successor));
        self::assertNotSame($rotationId, $successor);
        self::assertNotSame(RefreshTokenHasher::hash($rotationId), $successor);
    }

    /**
     * `successor()` is an HMAC-SHA256 keyed by the id over the package's
     * domain-separation label, so it matches a known vector and is not a plain
     * hash of the id.
     *
     * @return void
     */
    public function testSuccessorIsTheLabelledHmacOfTheRotationId(): void
    {
        $expected = rtrim(strtr(base64_encode(hash_hmac('sha256', 'sinemacula.laravel-authentication.refresh-rotation.v1', 'rotation-id', true)), '+/', '-_'), '=');

        self::assertSame($expected, RefreshTokenHasher::successor('rotation-id'));
        self::assertNotSame(rtrim(strtr(base64_encode(hash('sha256', 'rotation-id', true)), '+/', '-_'), '='), RefreshTokenHasher::successor('rotation-id'));
    }

    /**
     * Different ids have different successors, and following a chain of
     * successors does not return to an earlier id.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSuccessorChainsDoNotRepeat(): void
    {
        self::assertNotSame(RefreshTokenHasher::successor('rotation-a'), RefreshTokenHasher::successor('rotation-b'));

        $chain = [RefreshTokenHasher::generate()];

        for ($rotation = 0; $rotation < 16; $rotation++) {
            $chain[] = RefreshTokenHasher::successor($chain[array_key_last($chain)]);
        }

        self::assertSame($chain, array_values(array_unique($chain)));
    }

    /**
     * The plaintext id never appears in a stack trace through `successor()`.
     *
     * @return void
     */
    public function testSuccessorMarksItsParameterSensitive(): void
    {
        $parameter = (new \ReflectionMethod(RefreshTokenHasher::class, 'successor'))->getParameters()[0];

        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
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
