<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;

/**
 * Unit tests for the numeric setting reader every settings class shares: the
 * default, the forms and range it accepts, and the message it fails with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegerSetting::class)]
final class IntegerSettingTest extends TestCase
{
    /** @var string The key the tests read. */
    private const string KEY = 'authentication.example.ttl_seconds';

    /**
     * A setting that is not configured takes the default, which the caller
     * chooses.
     *
     * @return void
     */
    public function testTheDefaultAppliesWhenTheKeyIsNotSet(): void
    {
        self::assertSame(600, IntegerSetting::read(new Repository, self::KEY, 600, 60, 3600));
    }

    /**
     * Rows of `[value, least, greatest, what the reader returns]`: integers and
     * the digit strings `env()` returns, at each end of the range and between.
     *
     * @return iterable<string, array{0: int|string, 1: int, 2: int, 3: int}>
     */
    public static function provideAcceptedValues(): iterable
    {
        yield from [
            'least integer'        => [60, 60, 3600, 60],
            'greatest integer'     => [3600, 60, 3600, 3600],
            'least as a string'    => ['60', 60, 3600, 60],
            'greatest as a string' => ['3600', 60, 3600, 3600],
            'between, as a string' => ['900', 60, 3600, 900],
            'zero as a string'     => ['0', 0, 10, 0],
            'nine digits'          => ['999999999', 0, 999999999, 999999999],
            'a nine-digit integer' => [999999999, 0, 999999999, 999999999],
        ];
    }

    /**
     * Each accepted value is read as the integer it names.
     *
     * @param  int|string  $value
     * @param  int  $least
     * @param  int  $most
     * @param  int  $expected
     * @return void
     */
    #[DataProvider('provideAcceptedValues')]
    public function testReadsIntegersAndTheirDigitStrings(int|string $value, int $least, int $most, int $expected): void
    {
        $config = new Repository([]);

        $config->set(self::KEY, $value);

        self::assertSame($expected, IntegerSetting::read($config, self::KEY, 600, $least, $most));
    }

    /**
     * Rows of malformed or out-of-range values.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            'below the least'         => [59],
            'above the greatest'      => [3601],
            'below, as a string'      => ['59'],
            'above, as a string'      => ['3601'],
            'padded'                  => ['0600'],
            'signed'                  => ['+600'],
            'negative string'         => ['-600'],
            'with a trailing newline' => ["600\n"],
            'with leading space'      => [' 600'],
            'an exponent'             => ['6e2'],
            'a decimal string'        => ['600.0'],
            'ten digits'              => ['1000000000'],
            'a float'                 => [600.0],
            'null'                    => [null],
            'a boolean'               => [true],
            'an empty string'         => [''],
            'a list'                  => [[600]],
        ];
    }

    /**
     * Anything else fails closed, naming the key and the range.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesAnythingElse(mixed $value): void
    {
        $config = new Repository([]);

        $config->set(self::KEY, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.example.ttl_seconds must be an integer from 60 to 3600.');

        IntegerSetting::read($config, self::KEY, 600, 60, 3600);
    }

    /**
     * `IntegerSetting` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(IntegerSetting::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(IntegerSetting::class, $instance);
    }
}
