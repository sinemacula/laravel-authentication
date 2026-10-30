<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\CodeSettings;

/**
 * Unit tests for the one-time code settings: their defaults, the forms and
 * ranges they accept, and the key each malformed one is reported under.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeSettings::class)]
final class CodeSettingsTest extends TestCase
{
    /**
     * With no `codes` block, each number takes its default: 6 digits, 600
     * seconds, 5 attempts and a 60-second cooldown.
     *
     * @return void
     */
    public function testDefaultsApplyWhenNothingIsConfigured(): void
    {
        $settings = self::settings([]);

        self::assertSame([6, 600, 5, 60], [$settings->length(), $settings->ttlSeconds(), $settings->maxAttempts(), $settings->cooldownSeconds()]);
    }

    /**
     * Rows of `[key, value, what the reader returns]`: integers and the digit
     * strings `env()` returns, at each end of their range.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: int}>
     */
    public static function provideAcceptedNumbers(): iterable
    {
        yield from [
            'shortest code'           => ['length', 6, 6],
            'longest code'            => ['length', '10', 10],
            'shortest lifetime'       => ['ttl_seconds', 60, 60],
            'longest lifetime'        => ['ttl_seconds', '3600', 3600],
            'one attempt'             => ['max_attempts', '1', 1],
            'twenty attempts'         => ['max_attempts', 20, 20],
            'no cooldown'             => ['resend_cooldown_seconds', '0', 0],
            'cooldown of the default' => ['resend_cooldown_seconds', 600, 600],
        ];
    }

    /**
     * Each number is read as an integer, from an integer or its digit string.
     *
     * @param  string  $key
     * @param  int|string  $value
     * @param  int  $expected
     * @return void
     */
    #[DataProvider('provideAcceptedNumbers')]
    public function testReadsNumbersWithinTheirRange(string $key, int|string $value, int $expected): void
    {
        $settings = self::settings([$key => $value]);
        $readers  = [
            'length'                  => $settings->length(...),
            'ttl_seconds'             => $settings->ttlSeconds(...),
            'max_attempts'            => $settings->maxAttempts(...),
            'resend_cooldown_seconds' => $settings->cooldownSeconds(...),
        ];

        self::assertSame($expected, $readers[$key]());
    }

    /**
     * Rows of `[key, value, message]`: values out of range, of another type, or
     * strings that are not the canonical digits of an integer.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedNumbers(): iterable
    {
        yield from [
            'code too short'     => ['length', 5, 'authentication.codes.length must be an integer from 6 to 10.'],
            'code too long'      => ['length', '11', 'authentication.codes.length must be an integer from 6 to 10.'],
            'length null'        => ['length', null, 'authentication.codes.length must be an integer from 6 to 10.'],
            'length a float'     => ['length', 6.0, 'authentication.codes.length must be an integer from 6 to 10.'],
            'length padded'      => ['length', '06', 'authentication.codes.length must be an integer from 6 to 10.'],
            'length spaced'      => ['length', ' 6', 'authentication.codes.length must be an integer from 6 to 10.'],
            'length newline'     => ['length', "6\n", 'authentication.codes.length must be an integer from 6 to 10.'],
            'length negative'    => ['length', '-6', 'authentication.codes.length must be an integer from 6 to 10.'],
            'lifetime too short' => ['ttl_seconds', 59, 'authentication.codes.ttl_seconds must be an integer from 60 to 3600.'],
            'lifetime too long'  => ['ttl_seconds', 3601, 'authentication.codes.ttl_seconds must be an integer from 60 to 3600.'],
            'no attempts'        => ['max_attempts', 0, 'authentication.codes.max_attempts must be an integer from 1 to 20.'],
            'too many attempts'  => ['max_attempts', '21', 'authentication.codes.max_attempts must be an integer from 1 to 20.'],
            'attempts a bool'    => ['max_attempts', true, 'authentication.codes.max_attempts must be an integer from 1 to 20.'],
            'negative cooldown'  => ['resend_cooldown_seconds', -1, 'authentication.codes.resend_cooldown_seconds must be an integer from 0 to 600.'],
            'cooldown past ttl'  => ['resend_cooldown_seconds', 601, 'authentication.codes.resend_cooldown_seconds must be an integer from 0 to 600.'],
            'ten-digit string'   => ['ttl_seconds', '1000000000', 'authentication.codes.ttl_seconds must be an integer from 60 to 3600.'],
        ];
    }

    /**
     * A malformed number fails closed, naming the key and its range.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedNumbers')]
    public function testRefusesMalformedNumbers(string $key, mixed $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings([$key => $value])->validate();
    }

    /**
     * The cooldown's greatest value is the configured code lifetime.
     *
     * @return void
     */
    public function testTheCooldownIsBoundedByTheLifetime(): void
    {
        self::assertSame(120, self::settings(['ttl_seconds' => 120, 'resend_cooldown_seconds' => 120])->cooldownSeconds());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.codes.resend_cooldown_seconds must be an integer from 0 to 120.');

        self::settings(['ttl_seconds' => 120, 'resend_cooldown_seconds' => 121])->cooldownSeconds();
    }

    /**
     * Read every number once, so a malformed one fails `validate()`.
     *
     * @return void
     */
    public function testValidateReadsEveryNumber(): void
    {
        foreach (['length' => 11, 'max_attempts' => 0, 'resend_cooldown_seconds' => 601, 'ttl_seconds' => 59] as $key => $value) {
            try {
                self::settings([$key => $value])->validate();
                self::fail("validate() accepted a malformed {$key}.");
            } catch (\InvalidArgumentException $exception) {
                self::assertStringStartsWith("authentication.codes.{$key} must be", $exception->getMessage());
            }
        }
    }

    /**
     * Build the settings over a `codes` block.
     *
     * @param  array<string, mixed>  $codes
     * @return \SineMacula\Laravel\Authentication\Codes\CodeSettings
     */
    private static function settings(array $codes): CodeSettings
    {
        return new CodeSettings(new Repository(['authentication' => ['codes' => $codes]]));
    }
}
