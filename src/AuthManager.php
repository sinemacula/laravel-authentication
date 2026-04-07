<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Factory;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Package AuthManager.
 *
 * Subclass of Laravel's `AuthManager` that implements the package's
 * `Factory` marker contract and exposes seven contextual accessors
 * (`identity`, `principal`, `device`, `organization`, `scope`,
 * `isInternal`, `isExternal`) directly on the manager so the
 * framework `Auth::principal()` etc. calls work without relying on
 * `Macroable` registration. The accessors forward to the active
 * guard when it implements `ContextualGuard` and return the safe
 * fallback (`null` for nullable accessors, `false` for boolean
 * accessors) otherwise.
 *
 * Bound to the `auth` container key by `AuthServiceProvider`.
 * Intentionally not `final` so consumers may further subclass.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
class AuthManager extends IlluminateAuthManager implements Factory
{
    /**
     * Adopt the guard-driver and user-provider-driver registrations
     * from another `Illuminate\Auth\AuthManager` instance.
     *
     * Used by `AuthServiceProvider` when wrapping the framework's
     * existing manager so that any `Auth::extend(...)` /
     * `Auth::provider(...)` calls made before this provider booted
     * survive the container swap. Protected access from a descendant
     * class is the legitimate replacement for reflection here.
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
     * The active organization, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Organization
     */
    public function organization(): ?Organization
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->organization() : null;
    }

    /**
     * The active organization scope string, when resolvable.
     *
     * @return ?string
     */
    public function scope(): ?string
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->scope() : null;
    }

    /**
     * Whether the active principal is internal to its organization.
     *
     * Returns `false` for non-contextual guards or unauthenticated requests.
     *
     * @return bool
     */
    public function isInternal(): bool
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard && $guard->isInternal();
    }

    /**
     * Whether the active principal is external to its organization.
     *
     * Returns `false` for non-contextual guards or unauthenticated requests.
     *
     * @return bool
     */
    public function isExternal(): bool
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard && $guard->isExternal();
    }
}
