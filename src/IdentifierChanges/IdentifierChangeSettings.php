<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Illuminate\Contracts\Config\Repository;

/**
 * The identifier change settings in `authentication.identifier_changes`, read
 * on every call and validated as they are read: each number an integer, or the
 * digit string `env()` returns for one, within its range. Anything else fails
 * closed with an `InvalidArgumentException` naming the key;
 * `authentication:check` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentifierChangeSettings
{
    /** @var string Prefix of every identifier change setting's key. */
    private const string PREFIX = 'authentication.identifier_changes.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting. */
    private const array NUMBERS = [
        'ttl_seconds'                   => [3600, 300, 86400],
        'recent_authentication_seconds' => [900, 60, 86400],
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
     * How long a requested change waits to be confirmed, in seconds, 300 to
     * 86400.
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
     * How recently the identity must have authenticated to request a change, in
     * seconds, 60 to 86400.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function recentAuthenticationSeconds(): int
    {
        return $this->number('recent_authentication_seconds');
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
        $this->ttlSeconds();
        $this->recentAuthenticationSeconds();
    }

    /**
     * Read a numeric setting: an integer, or the canonical digit string of one,
     * from its least to its greatest value.
     *
     * @param  string  $key
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $key): int
    {
        [$default, $least, $most] = self::NUMBERS[$key];

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
