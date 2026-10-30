<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as RepositoryContract;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\NoBreachedPasswordCheck;
use SineMacula\Laravel\Authentication\Passwords\PasswordCheck;
use SineMacula\Laravel\Authentication\Passwords\PasswordPolicy;
use SineMacula\Laravel\Authentication\Passwords\PasswordSettings;
use SineMacula\Laravel\Authentication\Testing\FakeBreachedPasswordChecker;

/**
 * Unit tests for the password policy: which rule each password breaks under
 * each setting and at each bound, bcrypt's byte ceiling, and the breached check
 * with a checker that finds nothing, finds the password, or cannot answer,
 * failing closed or open.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordPolicy::class)]
#[CoversClass(PasswordCheck::class)]
#[CoversClass(NoBreachedPasswordCheck::class)]
final class PasswordPolicyTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Illuminate\Container\Container The container the policy resolves from. */
    private Container $container;

    /** @var \Illuminate\Config\Repository The configuration the policy reads. */
    private Repository $config;

    /** @var \ArrayObject<int, \Throwable> The exceptions reported to the handler. */
    private \ArrayObject $reported;

    /**
     * Build a container with the configuration, the default checker and a
     * handler that records what it is given.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reported  = new \ArrayObject;
        $this->config    = new Repository(['hashing' => ['driver' => 'argon2id']]);
        $this->container = new Container;

        $handler = \Mockery::mock(ExceptionHandler::class);

        $reported = $this->reported;

        $handler->shouldReceive('report')->andReturnUsing(static function (\Throwable $exception) use ($reported): void {
            $reported->append($exception);
        });

        $this->container->instance(RepositoryContract::class, $this->config);
        $this->container->instance(ExceptionHandler::class, $handler);
        $this->container->singleton(BreachedPasswordChecker::class, NoBreachedPasswordCheck::class);
    }

    /**
     * Rows of `[settings, password, violations]`: every rule at its bounds,
     * alone and together.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: list<string>}>
     */
    public static function provideVerdicts(): iterable
    {
        $all = ['letters' => true, 'mixed_case' => true, 'numbers' => true, 'symbols' => true];

        yield from [
            'one character short'                  => [[], str_repeat('a', 14), ['too_short']],
            'exactly the minimum'                  => [[], str_repeat('a', 15), []],
            'exactly the maximum'                  => [['max_length' => 20], str_repeat('a', 20), []],
            'one character over'                   => [['max_length' => 20], str_repeat('a', 21), ['too_long']],
            'characters, not bytes, count'         => [['min_length' => 8], 'ééééééé', ['too_short']],
            'multibyte at the minimum'             => [['min_length' => 8], 'éééééééé', []],
            'an empty password'                    => [[], '', ['too_short']],
            'no letter'                            => [['letters' => true], '123456789012345', ['letters']],
            'a letter from any script'             => [['letters' => true], '12345678901234ж', []],
            'one case only'                        => [['mixed_case' => true], 'alllowercaseletters', ['mixed_case']],
            'lower then upper'                     => [['mixed_case' => true], 'lowercaseThenUpper', []],
            'upper then lower'                     => [['mixed_case' => true], 'UPPERCASEthenlower', []],
            'no number'                            => [['numbers' => true], 'no numbers in here', ['numbers']],
            'a number from any script'             => [['numbers' => true], 'a number here: ٣ ok', []],
            'no symbol'                            => [['symbols' => true], 'NoSymbolsInHereAtAll', ['symbols']],
            'a space is a separator'               => [['symbols' => true], 'a space counts as one', []],
            'punctuation'                          => [['symbols' => true], 'punctuation!counts', []],
            'every rule broken'                    => [$all, str_repeat('1', 3), ['too_short', 'letters', 'mixed_case', 'symbols']],
            'every rule broken but numbers'        => [$all, '123456789012345', ['letters', 'mixed_case', 'symbols']],
            'every rule met'                       => [$all, 'Aa1!Aa1!Aa1!Aa1!', []],
            'composition is checked when too long' => [['max_length' => 15, 'numbers' => true], str_repeat('a', 16), ['too_long', 'numbers']],
            'invalid UTF-8 breaks every pattern'   => [['letters' => true], "abcdefghijklmnop\xff", ['letters']],
        ];
    }

    /**
     * Each password breaks exactly the rules listed, in the order the
     * violations are declared; one that breaks none passes.
     *
     * @param  array<string, mixed>  $settings
     * @param  string  $password
     * @param  list<string>  $expected
     * @return void
     */
    #[DataProvider('provideVerdicts')]
    public function testEachRuleAtItsBounds(array $settings, string $password, array $expected): void
    {
        $this->config->set('authentication.passwords', $settings);

        $check = $this->policy()->check($password);

        self::assertSame($expected, array_map(static fn (PasswordViolation $violation): string => $violation->value, $check->violations));
        self::assertSame($expected === [], $check->passes());
    }

    /**
     * Under bcrypt a password of more than 72 bytes is too long, however few
     * characters it has, since bcrypt would ignore the rest; under another
     * driver, or at exactly 72 bytes, it is not.
     *
     * @return void
     */
    public function testBcryptsByteCeilingOnlyUnderBcrypt(): void
    {
        $this->config->set('authentication.passwords.max_length', 4096);

        $multibyte = str_repeat('€', 25);

        self::assertSame(75, strlen($multibyte));
        self::assertSame([], $this->policy()->check($multibyte)->violations);
        self::assertSame([], $this->policy()->check(str_repeat('a', 73))->violations);

        $this->config->set('hashing.driver', 'bcrypt');

        self::assertSame([PasswordViolation::TOO_LONG], $this->policy()->check($multibyte)->violations);
        self::assertSame([PasswordViolation::TOO_LONG], $this->policy()->check(str_repeat('a', 73))->violations);
        self::assertSame([], $this->policy()->check(str_repeat('a', 72))->violations);
        self::assertSame([], $this->policy()->check(str_repeat('€', 24))->violations);
    }

    /**
     * Under bcrypt, which refuses to hash a null character, a password holding
     * one breaks that rule alongside any other, and the breached check is not
     * asked; under another driver it passes.
     *
     * @return void
     */
    public function testANullCharacterOnlyUnderBcrypt(): void
    {
        $checker = FakeBreachedPasswordChecker::fake([], $this->container);

        self::assertSame([], $this->policy()->check("correct horse battery\0staple")->violations);

        $this->config->set('hashing.driver', 'bcrypt');

        self::assertSame([PasswordViolation::NULL_CHARACTER], $this->policy()->check("correct horse battery\0staple")->violations);
        self::assertSame([PasswordViolation::NULL_CHARACTER], $this->policy()->check("\0correct horse battery staple")->violations);
        self::assertSame([PasswordViolation::TOO_SHORT, PasswordViolation::NULL_CHARACTER], $this->policy()->check("short\0")->violations);
        self::assertSame([], $this->policy()->check('correct horse battery staple')->violations);
        self::assertSame(["correct horse battery\0staple", 'correct horse battery staple'], $checker->checked());
    }

    /**
     * The breached check runs only for a password that passes the other rules,
     * and finds what the checker finds.
     *
     * @return void
     */
    public function testTheBreachedCheckRunsOnlyAfterTheOtherRulesPass(): void
    {
        $checker = FakeBreachedPasswordChecker::fake(['correct horse battery staple'], $this->container);

        self::assertSame([PasswordViolation::BREACHED], $this->policy()->check('correct horse battery staple')->violations);
        self::assertSame([], $this->policy()->check('a different passphrase')->violations);
        self::assertSame([PasswordViolation::TOO_SHORT], $this->policy()->check('short')->violations);
        self::assertSame(['correct horse battery staple', 'a different passphrase'], $checker->checked());
    }

    /**
     * A checker that cannot answer is reported, once, and the password is then
     * rejected as unchecked when the policy fails closed (the default) and
     * passes when it fails open.
     *
     * @return void
     */
    public function testAnUnavailableCheckerFailsClosedOrOpenAsConfigured(): void
    {
        FakeBreachedPasswordChecker::fake(container: $this->container)->unavailable();

        self::assertSame([PasswordViolation::BREACH_CHECK_UNAVAILABLE], $this->policy()->check('a long enough passphrase')->violations);
        self::assertCount(1, $this->reported);
        self::assertInstanceOf(BreachedPasswordCheckUnavailableException::class, $this->reported[0]);
        self::assertStringNotContainsString('a long enough passphrase', $this->reported[0]->getMessage());

        $this->config->set('authentication.passwords.breached.when_unavailable', 'allow');

        self::assertSame([], $this->policy()->check('a long enough passphrase')->violations);
        self::assertCount(2, $this->reported);
    }

    /**
     * Any other failure of the checker is not an outage the policy decides on:
     * it propagates, unreported.
     *
     * @return void
     */
    public function testAnyOtherCheckerFailurePropagates(): void
    {
        $checker = \Mockery::mock(BreachedPasswordChecker::class);

        $checker->shouldReceive('isBreached')->andThrow(new \RuntimeException('a bug in the checker'));

        $this->container->instance(BreachedPasswordChecker::class, $checker);

        try {
            $this->policy()->check('a long enough passphrase');
            self::fail('The checker\'s failure was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('a bug in the checker', $exception->getMessage());
        }

        self::assertCount(0, $this->reported);
    }

    /**
     * A malformed setting fails closed before any password is judged, even one
     * that the rest of the policy would let through without reading it.
     *
     * @return void
     */
    public function testAMalformedSettingFailsBeforeAnyCheck(): void
    {
        $checker = FakeBreachedPasswordChecker::fake(container: $this->container);

        $this->config->set('authentication.passwords.breached.when_unavailable', 'sometimes');

        try {
            $this->policy()->check('a long enough passphrase');
            self::fail('A malformed setting was ignored.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('authentication.passwords.breached.when_unavailable must be `reject` or `allow`.', $exception->getMessage());
        }

        self::assertSame(0, $checker->count());
    }

    /**
     * Rows of `[settings, the rules the Laravel rule applies]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array{min: int, max: int, mixedCase: bool, letters: bool, numbers: bool, symbols: bool}}>
     */
    public static function provideRules(): iterable
    {
        $none = ['mixedCase' => false, 'letters' => false, 'numbers' => false, 'symbols' => false];

        yield from [
            'the defaults'    => [[], ['min' => 15, 'max' => 128, ...$none]],
            'the lengths'     => [['min_length' => 9, 'max_length' => 64], ['min' => 9, 'max' => 64, ...$none]],
            'letters only'    => [['letters' => true], ['min' => 15, 'max' => 128, ...$none, 'letters' => true]],
            'mixed case only' => [['mixed_case' => true], ['min' => 15, 'max' => 128, ...$none, 'mixedCase' => true]],
            'numbers only'    => [['numbers' => true], ['min' => 15, 'max' => 128, ...$none, 'numbers' => true]],
            'symbols only'    => [['symbols' => true], ['min' => 15, 'max' => 128, ...$none, 'symbols' => true]],
            'every rule'      => [
                ['letters' => true, 'mixed_case' => true, 'numbers' => true, 'symbols' => true],
                ['min' => 15, 'max' => 128, 'mixedCase' => true, 'letters' => true, 'numbers' => true, 'symbols' => true],
            ],
        ];
    }

    /**
     * `rule()` is Laravel's `Password` rule with the configured lengths and
     * exactly the composition rules switched on, and never Laravel's own
     * breached check, which would call out to a service the application did not
     * choose.
     *
     * @param  array<string, mixed>  $settings
     * @param  array{min: int, max: int, mixedCase: bool, letters: bool, numbers: bool, symbols: bool}  $expected
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testTheRuleCarriesTheConfiguredPolicy(array $settings, array $expected): void
    {
        $this->config->set('authentication.passwords', $settings);

        $applied = $this->policy()->rule()->appliedRules();

        self::assertSame($expected, array_intersect_key($applied, $expected));
        self::assertFalse($applied['uncompromised']);
    }

    /**
     * The settings the policy reads are validated as a whole.
     *
     * @return void
     */
    public function testHandsOutValidatedSettings(): void
    {
        $this->config->set('authentication.passwords.min_length', 20);

        self::assertInstanceOf(PasswordSettings::class, $this->policy()->settings());
        self::assertSame(20, $this->policy()->settings()->minLength());

        $this->config->set('authentication.passwords.symbols', 'on');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.passwords.symbols must be true or false.');

        $this->policy()->settings();
    }

    /**
     * The policy over the test's container.
     *
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordPolicy
     */
    private function policy(): PasswordPolicy
    {
        return new PasswordPolicy($this->container);
    }
}
