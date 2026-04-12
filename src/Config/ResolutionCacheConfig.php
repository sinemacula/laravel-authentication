<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Config;

use Illuminate\Config\Repository as ConfigRepository;

/**
 * Resolution-cache runtime configuration resolver.
 *
 * Centralizes the package's optional shared auth-resolution cache settings so
 * the guard, cache adapter, and invalidator all observe live config changes
 * without reading globals directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class ResolutionCacheConfig
{
    /** @var int Default bearer identity TTL in seconds. `0` disables caching. */
    public const int DEFAULT_JWT_IDENTITY_TTL_SECONDS = 0;

    /** @var int Default bearer principal TTL in seconds. Reserved for future use. */
    public const int DEFAULT_JWT_PRINCIPAL_TTL_SECONDS = 0;

    /**
     * Constructor.
     *
     * @param  \Closure(): \Illuminate\Config\Repository  $configResolver
     */
    public function __construct(
        private readonly \Closure $configResolver,
    ) {}

    /**
     * Resolve the configured cache store name, or null for Laravel's default.
     *
     * @return ?string
     */
    public function store(): ?string
    {
        try {
            $store = $this->config()->string('authentication.resolution_cache.store', '');
        } catch (\Throwable) {
            return null;
        }

        return $store === '' ? null : $store;
    }

    /**
     * Resolve the bearer identity TTL in seconds.
     *
     * @return int
     */
    public function jwtIdentityTtlSeconds(): int
    {
        try {
            $configured = $this->config()->integer(
                'authentication.resolution_cache.jwt.identity_ttl_seconds',
                self::DEFAULT_JWT_IDENTITY_TTL_SECONDS,
            );
        } catch (\Throwable) {
            return self::DEFAULT_JWT_IDENTITY_TTL_SECONDS;
        }

        return max(0, $configured);
    }

    /**
     * Resolve the bearer principal TTL in seconds. Reserved for future use.
     *
     * @return int
     */
    public function jwtPrincipalTtlSeconds(): int
    {
        try {
            $configured = $this->config()->integer(
                'authentication.resolution_cache.jwt.principal_ttl_seconds',
                self::DEFAULT_JWT_PRINCIPAL_TTL_SECONDS,
            );
        } catch (\Throwable) {
            return self::DEFAULT_JWT_PRINCIPAL_TTL_SECONDS;
        }

        return max(0, $configured);
    }

    /**
     * Resolve the live config repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        return ($this->configResolver)();
    }
}
