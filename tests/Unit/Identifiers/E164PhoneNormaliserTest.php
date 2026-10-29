<?php

declare(strict_types = 1);

namespace Tests\Unit\Identifiers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Identifiers\E164PhoneNormaliser;

/**
 * Unit tests for the default phone normaliser, which accepts E.164 only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(E164PhoneNormaliser::class)]
final class E164PhoneNormaliserTest extends TestCase
{
    /**
     * Rows of `[given, normal form]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideNumbers(): iterable
    {
        yield from [
            'UK mobile'                 => ['+447700900123', '+447700900123'],
            'US number'                 => ['+12025550123', '+12025550123'],
            'shortest: country and one' => ['+12', '+12'],
            'longest: fifteen digits'   => ['+123456789012345', '+123456789012345'],
            'surrounding spaces'        => ['  +447700900123  ', '+447700900123'],
            'tabs, newlines and NUL'    => ["\t\n+447700900123\r\n\0", '+447700900123'],
        ];
    }

    /**
     * A number already in E.164 form is accepted, with surrounding whitespace
     * removed.
     *
     * @param  string  $given
     * @param  string  $normal
     * @return void
     */
    #[DataProvider('provideNumbers')]
    public function testAcceptsE164Numbers(string $given, string $normal): void
    {
        self::assertSame($normal, (new E164PhoneNormaliser)->normalise($given));
    }

    /**
     * Normalising a normal form returns it unchanged.
     *
     * @param  string  $given
     * @param  string  $normal
     * @return void
     */
    #[DataProvider('provideNumbers')]
    public function testNormalFormIsAFixedPoint(string $given, string $normal): void
    {
        $normaliser = new E164PhoneNormaliser;

        self::assertSame($normal, $normaliser->normalise($normaliser->normalise($given) ?? ''));
    }

    /**
     * Rows of values that are not E.164 numbers.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRejectedValues(): iterable
    {
        yield from [
            'empty'                   => [''],
            'blank'                   => [" \t\n"],
            'plus alone'              => ['+'],
            'one digit only'          => ['+4'],
            'sixteen digits'          => ['+1234567890123456'],
            'country code 0'          => ['+0447700900123'],
            'no plus'                 => ['447700900123'],
            'national format'         => ['07700 900123'],
            'international 00 prefix' => ['00447700900123'],
            'inner spaces'            => ['+44 7700 900123'],
            'dashes'                  => ['+44-7700-900123'],
            'brackets'                => ['+44 (0)7700 900123'],
            'two plus signs'          => ['++447700900123'],
            'letters'                 => ['+44770090012a'],
            'full-width digits'       => ['+４４７７００９００１２３'],
            'non-breaking space'      => ["\u{00A0}+447700900123"],
            'trailing newline inside' => ["+4477009\n00123"],
            'invalid UTF-8'           => ["+44770090\xC3\x28"],
        ];
    }

    /**
     * Anything that is not already E.164 is refused rather than parsed.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRejectedValues')]
    public function testRejectsAnythingElse(string $value): void
    {
        self::assertNull((new E164PhoneNormaliser)->normalise($value));
    }
}
