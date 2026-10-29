<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Illuminate\Contracts\Config\Repository;

/**
 * The one-time code settings in `authentication.codes`, read on every call and
 * validated as they are read: each number an integer, or the digit string
 * `env()` returns for one, within its range. Anything else fails closed with an
 * `InvalidArgumentException` naming the key; `authentication:check` reports it.
 * Delivery is queued with the `DeliverySettings`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeSettings
{
    /** @var string Prefix of every code setting's key. */
    private const string PREFIX = 'authentication.codes.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting; the cooldown's greatest is the code lifetime. */
    private const array NUMBERS = [
        'length'                  => [6, 6, 10],
        'ttl_seconds'             => [600, 60, 3600],
        'max_attempts'            => [5, 1, 20],
        'resend_cooldown_seconds' => [60, 0, 3600],
    ];

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
     * The number of digits in a code, 6 to 10.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function length(): int
    {
        return $this->number('length');
    }

    /**
     * How long a code works after it is issued, in seconds, 60 to 3600.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function ttlSeconds(): int
    {
        return $this->number('ttl_seconds');
    }

    /**
     * How many checks one code allows before it is locked, 1 to 20.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxAttempts(): int
    {
        return $this->number('max_attempts');
    }

    /**
     * How long after a code is issued another may be issued for the same
     * identifier, in seconds, from 0 to the code lifetime.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function cooldownSeconds(): int
    {
        return $this->number('resend_cooldown_seconds', $this->ttlSeconds());
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
        $this->length();
        $this->maxAttempts();
        $this->cooldownSeconds();
    }

    /**
     * Read a numeric setting: an integer, or the canonical digit string of one,
     * from its least to its greatest value (or `$greatest` when given).
     *
     * @param  string  $key
     * @param  ?int  $greatest
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $key, ?int $greatest = null): int
    {
        [$default, $least, $most] = self::NUMBERS[$key];

        $most  = $greatest ?? $most;
        $value = $this->config->get(self::PREFIX . $key, $default);

        if (is_string($value) && preg_match('/^(?:0|[1-9]\d{0,8})$/D', $value) === 1) {
            $value = (int) $value;
        }

        if (!is_int($value) || $value < $least || $value > $most) {
            throw new \InvalidArgumentException(sprintf('%s%s must be an integer from %d to %d.', self::PREFIX, $key, $least, $most));
        }

        return $value;
    }
}
