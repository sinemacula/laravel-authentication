<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Illuminate\Support\Facades\Config;

/**
 * The `authentication.api_keys` settings, read when they are needed, so the
 * keys, the guard, pruning and `authentication:check` judge them the same way.
 * Each number is an integer, or a digit string as `env()` returns one, within
 * its range; anything else fails closed with an `InvalidArgumentException`
 * naming the key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApiKeySettings
{
    /** @var int Longest rotation overlap that may be configured, in seconds: 30 days. */
    public const int MAX_ROTATION_OVERLAP_SECONDS = 2592000;

    /** @var string Pattern the key prefix must match. */
    private const string PREFIX_PATTERN = '/^[a-z][a-z0-9]{0,15}$/D';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The prefix a new key starts with: a lower-case letter, then up to 15
     * lower-case letters or digits.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function prefix(): string
    {
        $prefix = Config::get('authentication.api_keys.prefix', 'ak');

        if (!is_string($prefix) || preg_match(self::PREFIX_PATTERN, $prefix) !== 1) {
            throw new \InvalidArgumentException('`authentication.api_keys.prefix` must be a lower-case letter followed by up to 15 lower-case letters or digits.');
        }

        return $prefix;
    }

    /**
     * The overlap a rotation gives the replaced key by default, in seconds:
     * from 0 to the maximum overlap.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function rotationOverlapSeconds(): int
    {
        $max = self::maxRotationOverlapSeconds();

        return self::integer('rotation_overlap_seconds', 86400, 0, $max, "an integer from 0 to `max_rotation_overlap_seconds` ({$max}) seconds");
    }

    /**
     * The longest overlap a rotation may give the replaced key, in seconds:
     * from 0 to 30 days.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function maxRotationOverlapSeconds(): int
    {
        $max = self::MAX_ROTATION_OVERLAP_SECONDS;

        return self::integer('max_rotation_overlap_seconds', 604800, 0, $max, "an integer from 0 to {$max} seconds");
    }

    /**
     * How often a key's last use is recorded at most, in seconds: from 0 (every
     * use) to a day.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function lastUsedThrottleSeconds(): int
    {
        return self::integer('last_used_throttle_seconds', 60, 0, 86400, 'an integer from 0 to 86400 seconds');
    }

    /**
     * How long a revoked or expired key is kept before pruning deletes it, in
     * days: from 0 to 3650.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function pruneAfterDays(): int
    {
        return self::integer('prune_after_days', 30, 0, 3650, 'an integer from 0 to 3650 days');
    }

    /**
     * Read a setting that is an integer, or the digit string of one, within the
     * range.
     *
     * @param  string  $key
     * @param  int  $default
     * @param  int  $min
     * @param  int  $max
     * @param  string  $expected
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function integer(string $key, int $default, int $min, int $max, string $expected): int
    {
        $value = Config::get("authentication.api_keys.{$key}", $default);

        if (is_string($value) && preg_match('/^(0|[1-9]\d{0,9})$/D', $value) === 1) {
            $value = (int) $value;
        }

        if (!is_int($value) || $value < $min || $value > $max) {
            throw new \InvalidArgumentException("`authentication.api_keys.{$key}` must be {$expected}.");
        }

        return $value;
    }
}
