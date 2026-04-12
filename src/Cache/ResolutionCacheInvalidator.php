<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Cache;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Explicit shared-cache invalidator.
 *
 * Consumer applications are expected to call this from their identity-model
 * observers when they opt into bearer identity caching.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class ResolutionCacheInvalidator
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Cache\ResolutionCache  $cache
     * @param  \Closure(): \Illuminate\Config\Repository  $configResolver
     */
    public function __construct(
        private readonly ResolutionCache $cache,
        private readonly \Closure $configResolver,
    ) {}

    /**
     * Forget all JWT bearer identity cache entries that could resolve the
     * supplied identity model.
     *
     * Pass the previous auth identifier explicitly when invalidating after an
     * identifier change.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $identifier
     * @return void
     */
    public function forgetIdentity(Identity&Model $identity, mixed $identifier = null): void
    {
        $resolvedIdentifier = $identifier ?? $identity->getAuthIdentifier();

        foreach ($this->matchingJwtGuardProviderModels($identity) as $guardName => $providerModelClass) {
            $this->cache->forgetJwtIdentity($guardName, $providerModelClass, $resolvedIdentifier);
        }
    }

    /**
     * Forget a JWT bearer identity cache entry for a single guard.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guardName
     * @param  mixed  $identifier
     * @return void
     */
    public function forgetIdentityForGuard(Identity&Model $identity, string $guardName, mixed $identifier = null): void
    {
        $providerModelClass = $this->providerModelClassForJwtGuard($guardName, $identity);

        if ($providerModelClass === null) {
            return;
        }

        $this->cache->forgetJwtIdentity(
            $guardName,
            $providerModelClass,
            $identifier ?? $identity->getAuthIdentifier(),
        );
    }

    /**
     * Resolve the JWT guards whose model providers can return this identity.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return array<string, string>
     */
    private function matchingJwtGuardProviderModels(Identity&Model $identity): array
    {
        $matches = [];

        foreach ($this->config()->array('auth.guards', []) as $guardName => $guardConfig) {
            if (!is_string($guardName) || !is_array($guardConfig)) {
                continue;
            }

            $providerModelClass = $this->providerModelClassForJwtGuard($guardName, $identity);

            if ($providerModelClass !== null) {
                $matches[$guardName] = $providerModelClass;
            }
        }

        return $matches;
    }

    /**
     * Resolve the configured provider model class for a JWT guard, or null
     * when the guard is not a JWT/model-provider match for this identity.
     *
     * @param  string  $guardName
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return ?string
     */
    private function providerModelClassForJwtGuard(string $guardName, Identity&Model $identity): ?string
    {
        $guardConfig  = $this->config()->array('auth.guards.' . $guardName, []);
        $driver       = $guardConfig['driver']   ?? null;
        $providerName = $guardConfig['provider'] ?? null;

        if ($driver !== 'jwt' || !is_string($providerName) || $providerName === '') {
            return null;
        }

        $providerConfig     = $this->config()->array('auth.providers.' . $providerName, []);
        $providerDriver     = $providerConfig['driver'] ?? null;
        $providerModelClass = $providerConfig['model']  ?? null;

        if ($providerDriver !== 'model' || !is_string($providerModelClass) || $providerModelClass === '') {
            return null;
        }

        return is_a($identity, $providerModelClass) ? $providerModelClass : null;
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
