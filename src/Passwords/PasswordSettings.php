<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;

/**
 * The password policy settings in `authentication.passwords`, read on every
 * call and validated as they are read: each length an integer, or the digit
 * string `env()` returns for one, within its range; each composition rule a
 * boolean; the breached-check mode `reject` or `allow`; and the reset link
 * lifetime an integer within its range. Anything else fails closed with an
 * `InvalidArgumentException` naming the key; `authentication:check` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasswordSettings
{
    /** @var int Bytes of a password bcrypt reads; it ignores the rest. */
    public const int BCRYPT_BYTES = 72;

    /** @var string Prefix of every password setting's key. */
    private const string PREFIX = 'authentication.passwords.';

    /** @var list<'letters'|'mixed_case'|'numbers'|'symbols'> The composition rules, as Laravel's `Password` rule names them in snake case. */
    private const array COMPOSITION = ['letters', 'mixed_case', 'numbers', 'symbols'];

    /** @var list<string> What `breached.when_unavailable` may be. */
    private const array UNAVAILABLE_MODES = ['reject', 'allow'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The fewest characters a password may have, 8 to 128 (and at most 72 while
     * the hashing driver is bcrypt, which reads no more bytes).
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function minLength(): int
    {
        $min = $this->number('min_length', 15, 8, 128);

        if ($min > self::BCRYPT_BYTES && $this->hashesWithBcrypt()) {
            $message = sprintf('%smin_length must be at most %d while the hashing driver is bcrypt, which reads only that many bytes.', self::PREFIX, self::BCRYPT_BYTES);

            throw new \InvalidArgumentException($message);
        }

        return $min;
    }

    /**
     * The most characters a password may have, from the minimum to 4096.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxLength(): int
    {
        return $this->number('max_length', 128, $this->minLength(), 4096);
    }

    /**
     * Whether a password must hold a letter.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function requiresLetters(): bool
    {
        return $this->isOn('letters');
    }

    /**
     * Whether a password must hold both an upper-case and a lower-case letter.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function requiresMixedCase(): bool
    {
        return $this->isOn('mixed_case');
    }

    /**
     * Whether a password must hold a number.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function requiresNumbers(): bool
    {
        return $this->isOn('numbers');
    }

    /**
     * Whether a password must hold a symbol, punctuation or a separator.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function requiresSymbols(): bool
    {
        return $this->isOn('symbols');
    }

    /**
     * The composition rules switched on, in the order the violations are
     * listed.
     *
     * @return list<\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation::LETTERS|\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation::MIXED_CASE|\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation::NUMBERS|\SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation::SYMBOLS>
     *
     * @throws \InvalidArgumentException
     */
    public function compositionRules(): array
    {
        $rules = [];

        foreach (self::COMPOSITION as $rule) {

            if (!$this->isOn($rule)) {
                continue;
            }

            $rules[] = PasswordViolation::from($rule);
        }

        return $rules;
    }

    /**
     * Whether a password the breached-password checker cannot answer for is
     * rejected (`reject`, the default) rather than let through (`allow`).
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function rejectsWhenUnavailable(): bool
    {
        $mode = $this->config->get(self::PREFIX . 'breached.when_unavailable', 'reject');

        if (!is_string($mode) || !in_array($mode, self::UNAVAILABLE_MODES, true)) {
            throw new \InvalidArgumentException(sprintf('%sbreached.when_unavailable must be `reject` or `allow`.', self::PREFIX));
        }

        return $mode === 'reject';
    }

    /**
     * How long a password reset link works after it is requested, in seconds,
     * 300 to 86400.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function linkTtlSeconds(): int
    {
        return $this->number('reset.link_ttl_seconds', 3600, 300, 86400);
    }

    /**
     * Whether Laravel's hashing driver is bcrypt (its default), which reads
     * only the first 72 bytes of a password.
     *
     * @return bool
     */
    public function hashesWithBcrypt(): bool
    {
        return $this->config->get('hashing.driver', 'bcrypt') === 'bcrypt';
    }

    /**
     * Read every setting, failing closed on the first that is malformed;
     * `authentication:check` runs it.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->maxLength();
        $this->compositionRules();
        $this->rejectsWhenUnavailable();
        $this->linkTtlSeconds();
    }

    /**
     * Read an integer setting within its range (see `IntegerSetting`).
     *
     * @param  string  $key
     * @param  int  $default
     * @param  int  $least
     * @param  int  $most
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $key, int $default, int $least, int $most): int
    {
        return IntegerSetting::read($this->config, self::PREFIX . $key, $default, $least, $most);
    }

    /**
     * Read a composition rule: `true` or `false`, off when not set.
     *
     * @param  string  $key
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isOn(string $key): bool
    {
        $value = $this->config->get(self::PREFIX . $key, false);

        if (!is_bool($value)) {
            throw new \InvalidArgumentException(sprintf('%s%s must be true or false.', self::PREFIX, $key));
        }

        return $value;
    }
}
