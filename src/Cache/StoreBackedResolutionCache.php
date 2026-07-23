<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Cache;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Config\ResolutionCacheConfig;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\ResolutionCache;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Laravel-store-backed resolution cache.
 *
 * Fail-open by design: cache store failures fall back to live provider lookups
 * rather than denying auth or weakening refresh semantics.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class StoreBackedResolutionCache implements ResolutionCache
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Cache\Factory  $cache
     * @param  \SineMacula\Laravel\Authentication\Config\ResolutionCacheConfig  $config
     */
    public function __construct(

        /** Laravel cache factory for store resolution. */
        private CacheFactory $cache,

        /** Package resolution cache configuration. */
        private ResolutionCacheConfig $config,
    ) {}

    /**
     * Resolve and optionally cache a JWT bearer identity.
     *
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  mixed  $identifier
     * @param  callable(): ?\Illuminate\Contracts\Auth\Authenticatable  $resolver
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function rememberJwtIdentity(string $guardName, string $providerModelClass, mixed $identifier, callable $resolver): ?Authenticatable
    {
        $ttlSeconds           = $this->config->jwtIdentityTtlSeconds();
        $normalizedIdentifier = IdentifierCoercion::stringify($identifier);
        $cached               = $ttlSeconds > 0 && $normalizedIdentifier !== null
            ? $this->loadCachedIdentity($guardName, $providerModelClass, $normalizedIdentifier)
            : null;

        if ($cached !== null) {
            return $cached;
        }

        $resolved = $this->resolveLive($resolver);

        if ($ttlSeconds > 0 && $normalizedIdentifier !== null) {
            $this->storeResolvedIdentity(
                $guardName,
                $providerModelClass,
                $normalizedIdentifier,
                $ttlSeconds,
                $resolved,
            );
        }

        return $resolved;
    }

    /**
     * Forget a JWT bearer identity cache entry.
     *
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  mixed  $identifier
     * @return void
     */
    #[\Override]
    public function forgetJwtIdentity(string $guardName, string $providerModelClass, mixed $identifier): void
    {
        $normalizedIdentifier = IdentifierCoercion::stringify($identifier);

        if ($normalizedIdentifier === null) {
            return;
        }

        $this->forgetKey(
            $this->jwtIdentityKey($guardName, $providerModelClass, $normalizedIdentifier),
        );
    }

    /**
     * Load a cached JWT identity, forgetting unexpected payloads fail-open.
     *
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  string  $identifier
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    private function loadCachedIdentity(string $guardName, string $providerModelClass, string $identifier): ?Authenticatable
    {
        $key = $this->jwtIdentityKey($guardName, $providerModelClass, $identifier);

        try {
            $cached = $this->store()->get($key);
        } catch (\Throwable) {
            return null;
        }

        if ($cached instanceof Identity && $cached instanceof Model) {
            return $this->cloneIdentity($cached);
        }

        if ($cached !== null) {
            $this->forgetKey($key);
        }

        return null;
    }

    /**
     * Build the JWT bearer identity cache key.
     *
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  string  $identifier
     * @return string
     */
    private function jwtIdentityKey(string $guardName, string $providerModelClass, string $identifier): string
    {
        $providerSegment = str_replace('\\', '.', ltrim($providerModelClass, '\\'));

        return sprintf(
            'sm.auth.resolution.v1.jwt.%s.identity.%s.%s',
            $guardName,
            $providerSegment,
            $identifier,
        );
    }

    /**
     * Resolve the configured cache repository.
     *
     * @return \Illuminate\Contracts\Cache\Repository
     */
    private function store(): CacheRepository
    {
        $store = $this->config->store();

        return $store === null
            ? $this->cache->store()
            : $this->cache->store($store);
    }

    /**
     * Clone the cached identity so array-store hits do not share mutable model
     * instances across requests.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function cloneIdentity(Identity&Model $identity): Identity&Model
    {
        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity $clone */
        $clone = clone $identity;
        $clone->unsetRelations();

        return $clone;
    }

    /**
     * Remove a single cache key, swallowing store failures.
     *
     * @param  string  $key
     * @return void
     */
    private function forgetKey(string $key): void
    {
        try {
            $this->store()->forget($key);
        } catch (\Throwable) {
            // Fail open: an invalidation miss must not break auth flows.
        }
    }

    /**
     * Execute the live resolver and narrow the return to an Authenticatable.
     *
     * @param  callable(): ?\Illuminate\Contracts\Auth\Authenticatable  $resolver
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    private function resolveLive(callable $resolver): ?Authenticatable
    {
        $resolved = $resolver();

        return $resolved instanceof Authenticatable ? $resolved : null;
    }

    /**
     * Persist a resolved JWT identity when it is safely cacheable.
     *
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  string  $identifier
     * @param  int  $ttlSeconds
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $resolved
     * @return void
     */
    private function storeResolvedIdentity(string $guardName, string $providerModelClass, string $identifier, int $ttlSeconds, ?Authenticatable $resolved): void
    {
        if (!$resolved instanceof Identity || !$resolved instanceof Model) {
            return;
        }

        try {
            $this->store()->put(
                $this->jwtIdentityKey($guardName, $providerModelClass, $identifier),
                $this->cloneIdentity($resolved),
                $ttlSeconds,
            );
        } catch (\Throwable) {
            // Fail open: auth must not depend on cache writes succeeding.
        }
    }
}
