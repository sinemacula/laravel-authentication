<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ClientText;

/**
 * Unit tests for the cleaning of text a client supplied, before it is stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientText::class)]
final class ClientTextTest extends TestCase
{
    /**
     * Any client-supplied value is cleaned to the length asked for, counted in
     * characters, with NUL bytes removed and invalid UTF-8 replaced, and
     * nothing left reads as `null`.
     *
     * @return void
     */
    public function testCleanCutsToTheGivenLengthInCharacters(): void
    {
        self::assertSame('Pixé', ClientText::clean("Pi\0xé 9", 4));
        self::assertSame('ab?', ClientText::clean("ab\xC3", 3));
        self::assertNull(ClientText::clean("\0\0", 4));
        self::assertNull(ClientText::clean(null, 4));
    }

    /**
     * `ClientText` is a static utility; instantiation is disallowed through the
     * private constructor. Reflection invokes it so the line is covered while
     * still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ClientText::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }
}
