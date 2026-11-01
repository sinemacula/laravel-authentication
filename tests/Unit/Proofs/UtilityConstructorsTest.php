<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationMethods;
use SineMacula\Laravel\Authentication\Proofs\ProofAcceptance;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;

/**
 * The proof utility classes hold no state and cannot be instantiated: each
 * constructor is private. Reflection invokes it so the line is covered while
 * still documenting the access modifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationClaims::class)]
#[CoversClass(AuthenticationMethods::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ProofWriter::class)]
#[CoversClass(SessionProofs::class)]
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
            'claims'     => [AuthenticationClaims::class],
            'methods'    => [AuthenticationMethods::class],
            'acceptance' => [ProofAcceptance::class],
            'writer'     => [ProofWriter::class],
            'session'    => [SessionProofs::class],
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
