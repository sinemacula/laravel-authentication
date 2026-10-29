<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Support\Stringable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Identifiers\EmailNormaliser;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Passwords\ResetInput;

/**
 * Unit tests for how a reset request's and submission's input is read: only
 * strings (and, for an identifier, integers and `Stringable`s) reach a lookup
 * or a hash, and a code is bound only to a type with a normaliser.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetInput::class)]
final class ResetInputTest extends TestCase
{
    /**
     * Rows of `[value under the key, identifier read]`.
     *
     * @return iterable<string, array{0: mixed, 1: ?string}>
     */
    public static function provideIdentifiers(): iterable
    {
        yield from [
            'a string'     => ['ada@example.test', 'ada@example.test'],
            'an integer'   => [12345, '12345'],
            'a Stringable' => [new Stringable('ada@example.test'), 'ada@example.test'],
            'a float'      => [1.5, null],
            'a list'       => [['ada@example.test'], null],
            'a boolean'    => [true, null],
            'null'         => [null, null],
        ];
    }

    /**
     * The identifier is read as a string from a string, an integer or a
     * `Stringable`; anything else, or nothing, is `null`.
     *
     * @param  mixed  $value
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideIdentifiers')]
    public function testReadsTheIdentifier(mixed $value, ?string $expected): void
    {
        self::assertSame($expected, ResetInput::identifier(['email' => $value], 'email'));
        self::assertNull(ResetInput::identifier(['username' => $value], 'email'));
    }

    /**
     * A token, code or password is read only as a string.
     *
     * @return void
     */
    public function testReadsSecretsOnlyAsStrings(): void
    {
        self::assertSame('secret', ResetInput::secret(['token' => 'secret'], ResetInput::TOKEN_KEY));
        self::assertSame('', ResetInput::secret(['code' => ''], ResetInput::CODE_KEY));
        self::assertNull(ResetInput::secret(['password' => 12345678], ResetInput::PASSWORD_KEY));
        self::assertNull(ResetInput::secret(['password' => new Stringable('secret')], ResetInput::PASSWORD_KEY));
        self::assertNull(ResetInput::secret([], ResetInput::PASSWORD_KEY));
        self::assertSame(['token', 'code', 'password'], [ResetInput::TOKEN_KEY, ResetInput::CODE_KEY, ResetInput::PASSWORD_KEY]);
    }

    /**
     * A code is bound only to a valid type with a registered normaliser.
     *
     * @return void
     */
    public function testACodeNeedsANormalisedType(): void
    {
        $normalisers = new IdentifierNormalisers(new Container, new Repository(['authentication' => ['identifiers' => ['normalisers' => ['email' => EmailNormaliser::class]]]]));

        ResetInput::assertCodeType($normalisers, 'email');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Password reset codes need a normaliser registered for identifier type [phone] in `authentication.identifiers.normalisers`.');

        ResetInput::assertCodeType($normalisers, 'phone');
    }

    /**
     * `ResetInput` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ResetInput::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ResetInput::class, $instance);
    }
}
