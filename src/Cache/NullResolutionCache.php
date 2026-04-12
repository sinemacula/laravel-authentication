<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Cache;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * No-op resolution cache.
 *
 * Used by direct guard construction in tests/benchmarks and as the safe
 * fallback when callers do not supply a shared cache implementation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class NullResolutionCache implements ResolutionCache
{
    /**
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  mixed  $identifier
     * @param  callable(): ?\Illuminate\Contracts\Auth\Authenticatable  $resolver
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function rememberJwtIdentity(string $guardName, string $providerModelClass, mixed $identifier, callable $resolver): ?Authenticatable
    {
        unset($guardName, $providerModelClass, $identifier);

        $resolved = $resolver();

        return $resolved instanceof Authenticatable ? $resolved : null;
    }

    /**
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  mixed  $identifier
     * @return void
     */
    #[\Override]
    public function forgetJwtIdentity(string $guardName, string $providerModelClass, mixed $identifier): void
    {
        unset($guardName, $providerModelClass, $identifier);
    }
}
