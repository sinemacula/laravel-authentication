<?php

declare(strict_types = 1);

namespace Tests\Unit\Identifiers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;

/**
 * Unit tests for identifier type names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierType::class)]
final class IdentifierTypeTest extends TestCase
{
    /**
     * Rows of `[name, valid]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideNames(): iterable
    {
        yield from [
            'email'                  => ['email', true],
            'phone'                  => ['phone', true],
            'underscores and digits' => ['work_email_2', true],
            'single letter'          => ['e', true],
            'empty'                  => ['', false],
            'upper case'             => ['Email', false],
            'leading digit'          => ['2fa', false],
            'leading underscore'     => ['_email', false],
            'hyphen'                 => ['e-mail', false],
            'dot'                    => ['users.email', false],
            'space'                  => ['email ', false],
            'trailing newline'       => ["email\n", false],
            'SQL'                    => ['email; drop table users', false],
            'non-ASCII letter'       => ['émail', false],
        ];
    }

    /**
     * A type is a lower-case letter followed by lower-case letters, digits and
     * underscores.
     *
     * @param  string  $name
     * @param  bool  $valid
     * @return void
     */
    #[DataProvider('provideNames')]
    public function testOnlyColumnSafeLowerCaseNamesAreTypes(string $name, bool $valid): void
    {
        self::assertSame($valid, IdentifierType::isValid($name));

        if (!$valid) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('must be a lower-case letter followed by lower-case letters, digits and underscores.');
        }

        self::assertSame($name, IdentifierType::assertValid($name));
    }

    /**
     * The constructor is private; reflection invokes it for coverage.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(IdentifierType::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }
}
