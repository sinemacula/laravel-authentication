<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Support\Facades\Config;

/**
 * How long a device is kept once its session ended, before pruning deletes it:
 * `authentication.device.prune_after_days`, read when it is needed, so pruning
 * and `authentication:check` judge it the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeviceRetention
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The configured retention, in days: an integer, or a digit string as
     * `env()` returns one, from 0 to 3650.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function days(): int
    {
        $days = Config::get('authentication.device.prune_after_days', 30);

        if (is_string($days) && preg_match('/^(0|[1-9]\d{0,3})$/D', $days) === 1) {
            $days = (int) $days;
        }

        if (!is_int($days) || $days < 0 || $days > 3650) {
            throw new \InvalidArgumentException('`authentication.device.prune_after_days` must be an integer from 0 to 3650 days.');
        }

        return $days;
    }
}
