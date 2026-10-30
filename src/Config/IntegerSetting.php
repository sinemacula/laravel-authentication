<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Reads a numeric package setting the one way every settings class reads one:
 * an integer, or the canonical digit string `env()` returns for one (no sign,
 * padding or exponent, at most nine digits), within its range. Anything else
 * fails closed with an `InvalidArgumentException` naming the key and the range.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerSetting
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The setting under the key, or the default when it is not set, as an
     * integer from its least to its greatest value.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @param  int  $default
     * @param  int  $least
     * @param  int  $most
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function read(Repository $config, string $key, int $default, int $least, int $most): int
    {
        $value = $config->get($key, $default);

        if (is_string($value) && preg_match('/^(?:0|[1-9]\d{0,8})$/D', $value) === 1) {
            $value = (int) $value;
        }

        if (!is_int($value) || $value < $least || $value > $most) {
            throw new \InvalidArgumentException(sprintf('%s must be an integer from %d to %d.', $key, $least, $most));
        }

        return $value;
    }
}
