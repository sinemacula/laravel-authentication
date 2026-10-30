<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Validation\Rules\Password;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;

/**
 * The password policy a new password must pass: its length in characters, the
 * composition rules switched on, bcrypt's 72-byte ceiling and its refusal of a
 * null character when the hashing driver is bcrypt, and then the
 * breached-password check.
 *
 * Length counts characters as Laravel's `min` and `max` rules do (`mb_strlen`),
 * and the composition rules use exactly the expressions of Laravel's `Password`
 * rule, so `rule()` and `check()` agree on everything that rule can express.
 * The breached check runs only for a password that passes the rest; a checker
 * that cannot answer is reported to the exception handler, and the password is
 * then rejected (`reject`, the default) or let through (`allow`).
 *
 * It is applied to passwords being set, never to the automatic rehash of a
 * password on sign-in, which re-encodes a password the identity already holds.
 * The settings and the checker are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasswordPolicy
{
    /** @var array<string, string> Laravel's `Password` rule expression for each composition rule, by violation value. */
    private const array COMPOSITION = [
        'letters'    => '/\pL/u',
        'mixed_case' => '/(\p{Ll}+.*\p{Lu})|(\p{Lu}+.*\p{Ll})/u',
        'numbers'    => '/\pN/u',
        'symbols'    => '/\p{Z}|\p{S}|\p{P}/u',
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the configuration, checker and exception handler are resolved from. */
        private Container $container,
    ) {}

    /**
     * The policy's verdict on the password: every length and composition rule
     * it breaks, or, when it breaks none, the breached check's.
     *
     * @param  string  $password
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function check(#[\SensitiveParameter] string $password): PasswordCheck
    {
        $settings   = $this->settings();
        $violations = [
            ...$this->lengthViolations($settings, $password),
            ...self::hashingViolations($settings, $password),
            ...self::compositionViolations($settings, $password),
        ];

        if ($violations !== []) {
            return new PasswordCheck($violations);
        }

        $breached = $this->breachedViolation($settings, $password);

        return new PasswordCheck($breached === null ? [] : [$breached]);
    }

    /**
     * Laravel's `Password` rule with the configured length and composition, for
     * a form's validation. It cannot express the breached check or bcrypt's
     * byte ceiling and null character, so `check()` stays authoritative.
     *
     * @return \Illuminate\Validation\Rules\Password
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function rule(): Password
    {
        $settings = $this->settings();
        $rule     = Password::min($settings->minLength())->max($settings->maxLength());

        if ($settings->requiresLetters()) {
            $rule->letters();
        }

        if ($settings->requiresMixedCase()) {
            $rule->mixedCase();
        }

        if ($settings->requiresNumbers()) {
            $rule->numbers();
        }

        if ($settings->requiresSymbols()) {
            $rule->symbols();
        }

        return $rule;
    }

    /**
     * The settings, validated as a whole, so a malformed one fails closed
     * before any password is judged by the rest.
     *
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordSettings
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function settings(): PasswordSettings
    {
        $settings = new PasswordSettings($this->container->make(Repository::class));

        $settings->validate();

        return $settings;
    }

    /**
     * The length rules the password breaks: too few characters, or too many, or
     * more bytes than bcrypt reads.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordSettings  $settings
     * @param  string  $password
     * @return list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation>
     *
     * @throws \InvalidArgumentException
     */
    private function lengthViolations(PasswordSettings $settings, #[\SensitiveParameter] string $password): array
    {
        $length = mb_strlen($password);

        return match (true) {
            $length < $settings->minLength() => [PasswordViolation::TOO_SHORT],
            $length                                            > $settings->maxLength(),
            $settings->hashesWithBcrypt() && strlen($password) > PasswordSettings::BCRYPT_BYTES => [PasswordViolation::TOO_LONG],
            default                                                                             => [],
        };
    }

    /**
     * The rule the password breaks for the hasher: a null character, which
     * bcrypt refuses (PHP throws, and Laravel's hasher with it, rather than
     * hash it), while the hashing driver is bcrypt.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordSettings  $settings
     * @param  string  $password
     * @return list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation>
     */
    private static function hashingViolations(PasswordSettings $settings, #[\SensitiveParameter] string $password): array
    {
        return $settings->hashesWithBcrypt() && str_contains($password, "\0") ? [PasswordViolation::NULL_CHARACTER] : [];
    }

    /**
     * The composition rules switched on that the password breaks, in the order
     * the violations are listed.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordSettings  $settings
     * @param  string  $password
     * @return list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation>
     *
     * @throws \InvalidArgumentException
     */
    private static function compositionViolations(PasswordSettings $settings, #[\SensitiveParameter] string $password): array
    {
        $violations = [];

        foreach ($settings->compositionRules() as $rule) {

            if (preg_match(self::COMPOSITION[$rule->value], $password) === 1) {
                continue;
            }

            $violations[] = $rule;
        }

        return $violations;
    }

    /**
     * The breached check's verdict: `breached`, `breach_check_unavailable` when
     * the checker cannot answer and the policy fails closed, or `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordSettings  $settings
     * @param  string  $password
     * @return ?\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function breachedViolation(PasswordSettings $settings, #[\SensitiveParameter] string $password): ?PasswordViolation
    {
        try {
            return $this->container->make(BreachedPasswordChecker::class)->isBreached($password) ? PasswordViolation::BREACHED : null;
        } catch (BreachedPasswordCheckUnavailableException $exception) {
            $this->container->make(ExceptionHandler::class)->report($exception);

            return $settings->rejectsWhenUnavailable() ? PasswordViolation::BREACH_CHECK_UNAVAILABLE : null;
        }
    }
}
