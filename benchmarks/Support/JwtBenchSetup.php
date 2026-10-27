<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Shared configuration for the JWT bearer benchmarks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtBenchSetup
{
    /**
     * Build the package config repository backing the benchmarks.
     *
     * @return \Illuminate\Config\Repository
     */
    public static function config(): ConfigRepository
    {
        return new ConfigRepository([
            'authentication' => [
                'device' => [
                    'model'                      => Device::class,
                    'table'                      => 'devices',
                    'last_used_throttle_seconds' => 60,
                ],
                'timebox' => [
                    'credentials_microseconds' => 400000,
                ],
            ],
        ]);
    }
}
