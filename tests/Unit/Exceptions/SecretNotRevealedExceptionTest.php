<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException;

/**
 * Unit tests for the exception a secret used without being revealed throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretNotRevealedException::class)]
final class SecretNotRevealedExceptionTest extends TestCase
{
    /**
     * The exception names the use and how to send the secret, and is a logic
     * error: a bug in the calling code, never a result to handle.
     *
     * @return void
     */
    public function testNamesTheUseAndIsALogicError(): void
    {
        $exception = SecretNotRevealedException::for('logged');

        self::assertSame('A secret cannot be logged: call reveal() where it is to be sent.', $exception->getMessage());
        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertTrue((new \ReflectionClass(SecretNotRevealedException::class))->isFinal());
    }
}
