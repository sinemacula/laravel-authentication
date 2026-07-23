<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Shared auth-resolution cache boundary.
 *
 * V1 intentionally exposes only bearer identity caching. Basic credential
 * lookups, bearer device resolution, and the entire refresh flow remain
 * uncached.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ResolutionCache
{
    /**
     * Resolve and optionally cache a JWT bearer identity.
     *
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  mixed  $identifier
     * @param  callable(): ?\Illuminate\Contracts\Auth\Authenticatable  $resolver
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    public function rememberJwtIdentity(string $guardName, string $providerModelClass, mixed $identifier, callable $resolver): ?Authenticatable;

    /**
     * Forget a JWT bearer identity cache entry.
     *
     * @param  string  $guardName
     * @param  string  $providerModelClass
     * @param  mixed  $identifier
     * @return void
     */
    public function forgetJwtIdentity(string $guardName, string $providerModelClass, mixed $identifier): void;
}
