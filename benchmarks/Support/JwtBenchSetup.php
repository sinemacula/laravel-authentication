<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository;
use SineMacula\Laravel\Authentication\Cache\StoreBackedResolutionCache;
use SineMacula\Laravel\Authentication\Config\ResolutionCacheConfig;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Shared configuration and warm-cache wiring for the JWT bearer benchmarks.
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
                    'refresh_key_column'         => 'refresh_key',
                    'last_seen_throttle_seconds' => 60,
                ],
                'timebox' => [
                    'credentials_microseconds' => 400000,
                ],
                'resolution_cache' => [
                    'jwt' => [
                        'identity_ttl_seconds' => 15,
                    ],
                ],
            ],
        ]);
    }

    /**
     * Build the warm shared resolution cache over an in-memory array store.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return \SineMacula\Laravel\Authentication\Cache\StoreBackedResolutionCache
     */
    public static function warmResolutionCache(ConfigRepository $config): StoreBackedResolutionCache
    {
        return new StoreBackedResolutionCache(
            new class (new CacheRepository(new ArrayStore)) implements CacheFactory {
                /**
                 * Constructor.
                 *
                 * @param  \Illuminate\Cache\Repository  $repository
                 */
                public function __construct(

                    /** Shared array-backed cache repository. */
                    private readonly CacheRepository $repository,
                ) {}

                /**
                 * @param  string|\UnitEnum|null  $name
                 * @return \Illuminate\Contracts\Cache\Repository
                 */
                #[\Override]
                public function store($name = null): Repository
                {
                    unset($name);

                    return $this->repository;
                }
            },
            new ResolutionCacheConfig(
                static fn (): ConfigRepository => $config,
            ),
        );
    }
}
