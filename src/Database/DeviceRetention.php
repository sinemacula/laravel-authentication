<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;

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
    /** @var string Configuration key of the retention. */
    private const string KEY = 'authentication.device.prune_after_days';

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
        return IntegerSetting::from(self::KEY, Config::get(self::KEY, 30), 0, 3650);
    }
}
