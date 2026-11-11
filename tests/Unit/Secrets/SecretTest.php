<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for the value object every secret the package hands out is held
 * in: it gives the plaintext up only when revealed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Secret::class)]
final class SecretTest extends TestCase
{
    /** @var string The plaintext the tests hold. */
    private const string PLAINTEXT = 'eyJhbGciOiJIUzI1NiJ9.plaintext-payload.signature';

    /**
     * Revealing a secret gives the plaintext back exactly.
     *
     * @return void
     */
    public function testRevealGivesThePlaintext(): void
    {
        self::assertSame(self::PLAINTEXT, (new Secret(self::PLAINTEXT))->reveal());
    }

    /**
     * An empty secret is refused: nothing the package hands out is empty, so
     * one would be a bug.
     *
     * @return void
     */
    public function testAnEmptySecretIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A secret cannot be empty.');

        new Secret('');
    }

    /**
     * Rows of `[what is done to the secret, how the refusal names it]`.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Secrets\Secret): mixed, 1: string}>
     */
    public static function provideUnrevealedUses(): iterable
    {
        yield 'cast to a string' => [static fn (Secret $secret): string => (string) $secret, 'cast to a string'];
        yield 'concatenated' => [static fn (Secret $secret): string => 'Bearer ' . $secret, 'cast to a string'];
        yield 'encoded as JSON' => [static fn (Secret $secret): false|string => json_encode(['token' => $secret]), 'encoded as JSON'];
        yield 'encoded as JSON, throwing' => [static fn (Secret $secret): string => json_encode($secret, JSON_THROW_ON_ERROR), 'encoded as JSON'];
        yield 'serialised' => [static fn (Secret $secret): string => serialize($secret), 'serialised'];
        yield 'serialised inside an array' => [static fn (Secret $secret): string => serialize(['tokens' => [$secret]]), 'serialised'];
    }

    /**
     * Using a secret in any way but `reveal()` throws, naming the use and never
     * the plaintext.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Secrets\Secret): mixed  $use
     * @param  string  $named
     * @return void
     */
    #[DataProvider('provideUnrevealedUses')]
    public function testEveryUnrevealedUseThrows(\Closure $use, string $named): void
    {
        try {
            $use(new Secret(self::PLAINTEXT));
        } catch (SecretNotRevealedException $exception) {
            self::assertSame("A secret cannot be {$named}: call reveal() where it is to be sent.", $exception->getMessage());
            self::assertStringNotContainsString(self::PLAINTEXT, $exception->getMessage());

            return;
        }

        self::fail('The secret was used without being revealed.');
    }

    /**
     * A payload that would unserialise into a secret is refused, so a secret
     * cannot be planted in a cache or a queue and read back.
     *
     * @return void
     */
    public function testUnserialisingIsRefused(): void
    {
        $this->expectException(SecretNotRevealedException::class);
        $this->expectExceptionMessage('A secret cannot be unserialised: call reveal() where it is to be sent.');

        unserialize('O:' . strlen(Secret::class) . ':"' . Secret::class . '":1:{s:5:"value";s:9:"plaintext";}');
    }

    /**
     * No dump shows the plaintext, and those that use the debug information
     * show the placeholder.
     *
     * @return void
     */
    public function testNoDumpShowsThePlaintext(): void
    {
        $secret = new Secret(self::PLAINTEXT);

        $dumps = [
            'print_r'    => print_r($secret, true),
            'var_export' => var_export($secret, true),
            'VarDumper'  => (string) (new CliDumper)->dump((new VarCloner)->cloneVar($secret), true),
            'array cast' => print_r((array) $secret, true),
        ];

        foreach ($dumps as $dump => $output) {
            self::assertStringNotContainsString(self::PLAINTEXT, $output, $dump);
        }

        self::assertSame(['secret' => Secret::REDACTED], $secret->__debugInfo());

        foreach (['print_r', 'VarDumper'] as $dump) {
            self::assertStringContainsString(Secret::REDACTED, $dumps[$dump], $dump);
        }
    }

    /**
     * A trace records a secret as the object, never its plaintext, even when
     * one is built.
     *
     * @return void
     */
    public function testATraceHoldsNoPlaintext(): void
    {
        $ignored = ini_set('zend.exception_ignore_args', '0');
        $trace   = [];

        try {
            (static function (Secret $secret): never {
                throw new \RuntimeException('a bug while sending ' . $secret::class);
            })(new Secret(self::PLAINTEXT));
        } catch (\RuntimeException $exception) {
            $trace = $exception->getTrace();
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }

        self::assertInstanceOf(Secret::class, $trace[0]['args'][0] ?? null);
        self::assertStringNotContainsString(self::PLAINTEXT, print_r($trace, true));
        self::assertStringNotContainsString(self::PLAINTEXT, (string) (new CliDumper)->dump((new VarCloner)->cloneVar($trace), true));
        self::assertNotSame([], (new \ReflectionParameter([Secret::class, '__construct'], 'value'))->getAttributes(\SensitiveParameter::class));
    }

    /**
     * A secret is a final, read-only value: nothing can subclass it to add a
     * way out, nor change the plaintext it holds.
     *
     * @return void
     */
    public function testASecretIsAFinalReadOnlyValue(): void
    {
        $class = new \ReflectionClass(Secret::class);

        self::assertTrue($class->isFinal());
        self::assertTrue($class->isReadOnly());
        self::assertSame(['value'], array_map(static fn (\ReflectionProperty $property): string => $property->getName(), $class->getProperties()));
        self::assertTrue($class->getProperty('value')->isPrivate());
    }
}
