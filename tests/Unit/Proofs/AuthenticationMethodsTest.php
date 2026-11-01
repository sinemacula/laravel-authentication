<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationMethods;

/**
 * Unit tests for a proof's `amr` values: the list a proof may carry, and the
 * values read back from a stored proof.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationMethods::class)]
final class AuthenticationMethodsTest extends TestCase
{
    /** @var string The refusal of values that are no list or too many. */
    private const string NOT_A_LIST = 'A proof\'s `amr` values must be a list of at most 8.';

    /** @var string The refusal of a value that is no string or misshapen. */
    private const string MISSHAPEN = 'A proof\'s `amr` value must be 1 to 48 printable ASCII characters, no quote or backslash.';

    /** @var string The refusal of the reserved value. */
    private const string RESERVED = '`mfa` is reserved: it is never a proof\'s own `amr` value, only an accepted evaluation\'s report.';

    /**
     * Rows of `[values]` a proof may carry.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideAccepted(): iterable
    {
        yield from [
            'none'                  => [[]],
            'one'                   => [['pwd']],
            'several in order'      => [['otp', 'pwd', 'hwk']],
            'the most there may be' => [['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']],
            'the longest value'     => [[str_repeat('x', 48)]],
            'every printable kind'  => [['!#$%&()*+,-./09:;<=>?@AZ[]^_`az{|}~']],
        ];
    }

    /**
     * A list of at most eight values of 1 to 48 printable ASCII characters, none
     * of them `mfa`, is kept whole and in order.
     *
     * @param  list<string>  $methods
     * @return void
     */
    #[DataProvider('provideAccepted')]
    public function testAValidListIsKeptWhole(array $methods): void
    {
        self::assertSame($methods, AuthenticationMethods::assertValid($methods));
    }

    /**
     * Rows of `[values, message]` a proof may not carry.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function provideRefused(): iterable
    {
        yield from [
            'one too many'        => [['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'], self::NOT_A_LIST],
            'a map'               => [['first' => 'pwd'], self::NOT_A_LIST],
            'a list out of order' => [[1 => 'pwd', 0 => 'otp'], self::NOT_A_LIST],
            'a number'            => [['pwd', 7], self::MISSHAPEN],
            'null'                => [[null], self::MISSHAPEN],
            'an empty value'      => [[''], self::MISSHAPEN],
            'a value too long'    => [[str_repeat('x', 49)], self::MISSHAPEN],
            'a space'             => [['p d'], self::MISSHAPEN],
            'a quote'             => [['p"d'], self::MISSHAPEN],
            'a backslash'         => [['p\d'], self::MISSHAPEN],
            'a non-ASCII value'   => [['pwé'], self::MISSHAPEN],
            'a trailing newline'  => [["pwd\n"], self::MISSHAPEN],
            'mfa'                 => [['pwd', 'mfa'], self::RESERVED],
        ];
    }

    /**
     * Values that are no list, too many, or hold one that is no string, is
     * misshapen or is `mfa`, are refused.
     *
     * @param  array<array-key, mixed>  $methods
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefused')]
    public function testAnInvalidListIsRefused(array $methods, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        AuthenticationMethods::assertValid($methods);
    }

    /**
     * The values a stored proof kept are its strings as a list, in order;
     * anything else it holds is no value, and a row that holds no array has
     * none.
     *
     * @return void
     */
    public function testTheKeptValuesAreTheStringsAsAList(): void
    {
        self::assertSame(['pwd', 'otp'], AuthenticationMethods::kept([7, 'pwd', null, 'otp']));
        self::assertSame(['pwd', 'otp'], AuthenticationMethods::kept(['first' => 'pwd', 'second' => 'otp']));
        self::assertSame([], AuthenticationMethods::kept('pwd'));
        self::assertSame([], AuthenticationMethods::kept(null));
    }
}
