<?php

declare(strict_types = 1);

namespace Tests\Unit\Identifiers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Identifiers\EmailNormaliser;

/**
 * Unit tests for the default email normaliser.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EmailNormaliser::class)]
final class EmailNormaliserTest extends TestCase
{
    /**
     * Rows of `[given, normal form]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideAddresses(): iterable
    {
        yield from [
            'already normal'           => ['ben@example.com', 'ben@example.com'],
            'upper case everywhere'    => ['Ben.Carey@Example.COM', 'ben.carey@example.com'],
            'surrounding spaces'       => ['  ben@example.com  ', 'ben@example.com'],
            'tabs, newlines and NUL'   => ["\t\nben@example.com\r\n\0", 'ben@example.com'],
            'inner spaces kept'        => [' a b@example.com ', 'a b@example.com'],
            'non-ASCII letters'        => ['ÉMILE@Exemple.FR', 'émile@exemple.fr'],
            'German sharp s capital'   => ['STRAẞE@example.de', 'straße@example.de'],
            'no at sign is not judged' => ['Not An Address', 'not an address'],
        ];
    }

    /**
     * An address is trimmed and lower-cased in full, local part included, and
     * is otherwise left alone: format checks belong to validation.
     *
     * @param  string  $given
     * @param  string  $normal
     * @return void
     */
    #[DataProvider('provideAddresses')]
    public function testNormalisesToTrimmedLowerCase(string $given, string $normal): void
    {
        self::assertSame($normal, (new EmailNormaliser)->normalise($given));
    }

    /**
     * Normalising a normal form returns it unchanged, so normalising twice is
     * the same as once.
     *
     * @param  string  $given
     * @param  string  $normal
     * @return void
     */
    #[DataProvider('provideAddresses')]
    public function testNormalFormIsAFixedPoint(string $given, string $normal): void
    {
        $normaliser = new EmailNormaliser;

        self::assertSame($normal, $normaliser->normalise($normaliser->normalise($given) ?? ''));
    }

    /**
     * Rows of values that cannot be an address.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRejectedValues(): iterable
    {
        yield from [
            'empty'           => [''],
            'blank'           => [" \t\n"],
            'invalid UTF-8'   => ["ben\xC3\x28@example.com"],
            'truncated UTF-8' => ["ben@example.com\xE2\x82"],
        ];
    }

    /**
     * A blank value or one that is not valid UTF-8 is not an address.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRejectedValues')]
    public function testRejectsValuesThatCannotBeAnAddress(string $value): void
    {
        self::assertNull((new EmailNormaliser)->normalise($value));
    }
}
