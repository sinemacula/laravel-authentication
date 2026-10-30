<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;

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

    /** @var string Prefix of every API key setting's key. */
    private const string PREFIX = 'authentication.api_keys.';

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
        $prefix = Config::get(self::PREFIX . 'prefix', 'ak');

        if (!is_string($prefix) || preg_match(self::PREFIX_PATTERN, $prefix) !== 1) {
            throw new \InvalidArgumentException(self::PREFIX . 'prefix must be a lower-case letter followed by up to 15 lower-case letters or digits.');
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
        $max     = self::maxRotationOverlapSeconds();
        $overlap = IntegerSetting::parse(Config::get(self::PREFIX . 'rotation_overlap_seconds', 86400));

        if ($overlap === null || $overlap < 0 || $overlap > $max) {
            $message = self::PREFIX . 'rotation_overlap_seconds must be an integer from 0 to '
                . self::PREFIX . "max_rotation_overlap_seconds ({$max}).";

            throw new \InvalidArgumentException($message);
        }

        return $overlap;
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
        return self::integer('max_rotation_overlap_seconds', 604800, 0, self::MAX_ROTATION_OVERLAP_SECONDS);
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
        return self::integer('last_used_throttle_seconds', 60, 0, 86400);
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
        return self::integer('prune_after_days', 30, 0, 3650);
    }

    /**
     * Read a numeric setting within its range (see `IntegerSetting`).
     *
     * @param  string  $key
     * @param  int  $default
     * @param  int  $least
     * @param  int  $most
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function integer(string $key, int $default, int $least, int $most): int
    {
        return IntegerSetting::from(self::PREFIX . $key, Config::get(self::PREFIX . $key, $default), $least, $most);
    }
}
