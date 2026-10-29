<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\PasswordSettings;

/**
 * Unit tests for the password policy settings: their defaults, the forms and
 * ranges they accept, the key each malformed one is reported under, and the
 * bcrypt ceiling on the minimum length.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordSettings::class)]
final class PasswordSettingsTest extends TestCase
{
    /** @var string What a minimum past bcrypt's bytes is refused with. */
    private const string BCRYPT_MINIMUM = 'authentication.passwords.min_length must be at most 72 while the hashing driver is bcrypt, which reads only that many bytes.';

    /** @var string What an unknown breached-check mode is refused with. */
    private const string BREACHED_MODE = 'authentication.passwords.breached.when_unavailable must be `reject` or `allow`.';

    /**
     * With no `passwords` block, the policy is NIST's for a single factor: 15
     * to 128 characters, no composition rule, and an unavailable breached check
     * fails closed; Laravel's default hashing driver is bcrypt.
     *
     * @return void
     */
    public function testDefaultsApplyWhenNothingIsConfigured(): void
    {
        $settings = self::settings([]);

        self::assertSame([15, 128], [$settings->minLength(), $settings->maxLength()]);
        self::assertSame([false, false, false, false], [$settings->requiresLetters(), $settings->requiresMixedCase(), $settings->requiresNumbers(), $settings->requiresSymbols()]);
        self::assertTrue($settings->rejectsWhenUnavailable());
        self::assertTrue($settings->hashesWithBcrypt());
    }

    /**
     * Every setting is read as configured: lengths from integers or the digit
     * strings `env()` returns, each composition rule on, and the breached check
     * failing open.
     *
     * @return void
     */
    public function testReadsTheConfiguredPolicy(): void
    {
        $settings = self::settings([
            'min_length' => '8',
            'max_length' => 4096,
            'letters'    => true,
            'mixed_case' => true,
            'numbers'    => true,
            'symbols'    => true,
            'breached'   => ['when_unavailable' => 'allow'],
        ], 'argon2id');

        self::assertSame([8, 4096], [$settings->minLength(), $settings->maxLength()]);
        self::assertSame([true, true, true, true], [$settings->requiresLetters(), $settings->requiresMixedCase(), $settings->requiresNumbers(), $settings->requiresSymbols()]);
        self::assertFalse($settings->rejectsWhenUnavailable());
        self::assertFalse($settings->hashesWithBcrypt());
    }

    /**
     * Rows of `[block, hashing driver, message]` for settings that fail closed.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'minimum below 8'            => [['min_length' => 7], 'argon2id', 'authentication.passwords.min_length must be an integer from 8 to 128.'],
            'minimum above 128'          => [['min_length' => '129'], 'argon2id', 'authentication.passwords.min_length must be an integer from 8 to 128.'],
            'minimum a float'            => [['min_length' => 12.0], 'argon2id', 'authentication.passwords.min_length must be an integer from 8 to 128.'],
            'minimum padded'             => [['min_length' => '012'], 'argon2id', 'authentication.passwords.min_length must be an integer from 8 to 128.'],
            'minimum with a newline'     => [['min_length' => "12\n"], 'argon2id', 'authentication.passwords.min_length must be an integer from 8 to 128.'],
            'minimum null'               => [['min_length' => null], 'argon2id', 'authentication.passwords.min_length must be an integer from 8 to 128.'],
            'minimum past bcrypt'        => [['min_length' => 73], 'bcrypt', self::BCRYPT_MINIMUM],
            'maximum below the minimum'  => [['min_length' => 20, 'max_length' => 19], 'argon2id', 'authentication.passwords.max_length must be an integer from 20 to 4096.'],
            'maximum above 4096'         => [['max_length' => 4097], 'argon2id', 'authentication.passwords.max_length must be an integer from 15 to 4096.'],
            'maximum a word'             => [['max_length' => 'long'], 'argon2id', 'authentication.passwords.max_length must be an integer from 15 to 4096.'],
            'letters a string'           => [['letters' => 'true'], 'argon2id', 'authentication.passwords.letters must be true or false.'],
            'mixed case a number'        => [['mixed_case' => 1], 'argon2id', 'authentication.passwords.mixed_case must be true or false.'],
            'numbers null'               => [['numbers' => null], 'argon2id', 'authentication.passwords.numbers must be true or false.'],
            'symbols a list'             => [['symbols' => [true]], 'argon2id', 'authentication.passwords.symbols must be true or false.'],
            'an unknown breached mode'   => [['breached' => ['when_unavailable' => 'ignore']], 'argon2id', self::BREACHED_MODE],
            'a breached mode in caps'    => [['breached' => ['when_unavailable' => 'REJECT']], 'argon2id', self::BREACHED_MODE],
            'a breached mode not a name' => [['breached' => ['when_unavailable' => false]], 'argon2id', self::BREACHED_MODE],
        ];
    }

    /**
     * A malformed setting fails `validate()` closed, naming the key and what it
     * may be.
     *
     * @param  array<string, mixed>  $block
     * @param  string  $driver
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testRefusesMalformedSettings(array $block, string $driver, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings($block, $driver)->validate();
    }

    /**
     * The composition rules switched on are listed in the order the violations
     * are declared, whatever order the configuration names them in.
     *
     * @return void
     */
    public function testListsTheCompositionRulesSwitchedOn(): void
    {
        self::assertSame([], self::settings([])->compositionRules());
        $some = self::settings(['symbols' => true, 'mixed_case' => true, 'letters' => false]);

        self::assertSame([PasswordViolation::MIXED_CASE, PasswordViolation::SYMBOLS], $some->compositionRules());
        self::assertSame(
            [PasswordViolation::LETTERS, PasswordViolation::MIXED_CASE, PasswordViolation::NUMBERS, PasswordViolation::SYMBOLS],
            self::settings(['numbers' => true, 'symbols' => true, 'letters' => true, 'mixed_case' => true])->compositionRules(),
        );
    }

    /**
     * Under bcrypt the minimum may reach 72, the bytes bcrypt reads, and under
     * another driver the whole range.
     *
     * @return void
     */
    public function testBcryptCapsTheMinimumAtItsBytes(): void
    {
        self::assertSame(72, self::settings(['min_length' => 72], 'bcrypt')->minLength());
        self::assertSame(128, self::settings(['min_length' => 128], 'argon2id')->minLength());
    }

    /**
     * Build the settings over a `passwords` block and a hashing driver.
     *
     * @param  array<string, mixed>  $block
     * @param  string  $driver
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordSettings
     */
    private static function settings(array $block, string $driver = 'bcrypt'): PasswordSettings
    {
        return new PasswordSettings(new Repository(['authentication' => ['passwords' => $block], 'hashing' => ['driver' => $driver]]));
    }
}
