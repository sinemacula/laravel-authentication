<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Factory;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Package AuthManager.
 *
 * Subclass of Laravel's `AuthManager` that exposes the contextual
 * accessors (`identity`, `principal`, `device`, `tenant`, `type`)
 * directly on the manager. Each accessor forwards to the active
 * guard when it implements `ContextualGuard`, otherwise returns
 * `null`. Bound to the `auth` container key by
 * `AuthServiceProvider`. Not `final` so consumers may subclass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class AuthManager extends IlluminateAuthManager implements Factory
{
    /**
     * Adopt the guard-driver and user-provider-driver registrations
     * from another `Illuminate\Auth\AuthManager` instance so that any
     * `Auth::extend(...)` / `Auth::provider(...)` calls made before
     * this provider booted survive the container swap.
     *
     * @param  \Illuminate\Auth\AuthManager  $existing
     * @return void
     */
    public function inheritDriversFrom(IlluminateAuthManager $existing): void
    {
        if ($existing->customCreators !== []) {
            $this->customCreators = $existing->customCreators;
        }

        if ($existing->customProviderCreators !== []) {
            $this->customProviderCreators = $existing->customProviderCreators;
        }
    }

    /**
     * The active identity, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    public function identity(): ?Identity
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->identity() : null;
    }

    /**
     * The active principal, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function principal(): ?Principal
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->principal() : null;
    }

    /**
     * The active device, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    public function device(): ?Device
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->device() : null;
    }

    /**
     * The active tenant, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    public function tenant(): ?Tenant
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->tenant() : null;
    }

    /**
     * The active tenant's type string, when resolvable.
     *
     * @return ?string
     */
    public function type(): ?string
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->type() : null;
    }
}
