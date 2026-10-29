<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Package AuthManager.
 *
 * Subclass of Laravel's `AuthManager` that exposes the contextual accessors
 * (`identity`, `principal`, `device`, `tenant`, `type`), guard-scoped `jwt()`
 * issuance and each JWT guard's `sessions()` and `refreshTransport()` directly
 * on the manager. Each contextual accessor forwards to the active guard when it
 * implements `ContextualGuard`, otherwise returns `null`. Bound to the `auth`
 * container key by `AuthenticationServiceProvider`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @inheritable
 */
class AuthManager extends IlluminateAuthManager
{
    /**
     * Adopt the guard-driver and user-provider-driver registrations from
     * another `Illuminate\Auth\AuthManager` instance so that any
     * `Auth::extend(...)` / `Auth::provider(...)` calls made before this
     * provider booted survive the container swap.
     *
     * @param  \Illuminate\Auth\AuthManager  $existing
     * @return void
     */
    public function inheritDriversFrom(IlluminateAuthManager $existing): void
    {
        if ($existing->customCreators !== []) {
            $this->customCreators = $existing->customCreators;
        }

        if ($existing->customProviderCreators === []) {
            return;
        }

        $this->customProviderCreators = $existing->customProviderCreators;
    }

    /**
     * Build a guard-scoped `JwtTokenService` for the named guard, or for the
     * current default guard when the name is omitted.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     *
     * @throws \InvalidArgumentException
     */
    public function jwt(?string $guard = null): JwtTokenService
    {
        $guardName = $guard ?? $this->getDefaultDriver();

        if ($guardName === '') {
            throw new \InvalidArgumentException('No default auth guard is configured.');
        }

        /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory $factory */
        $factory = $this->app->make(JwtTokenServiceFactory::class);

        return $factory->forGuard($guardName);
    }

    /**
     * Return the session service of the named JWT guard, or of the current
     * default guard when the name is omitted.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \InvalidArgumentException
     */
    public function sessions(?string $guard = null): SessionService
    {
        return $this->jwtGuard($guard, 'session service')->sessions();
    }

    /**
     * Return the refresh token transport of the named JWT guard, or of the
     * current default guard when the name is omitted, to read a refresh token
     * from a request through the one source the guard allows.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     *
     * @throws \InvalidArgumentException
     */
    public function refreshTransport(?string $guard = null): RefreshTokenTransport
    {
        return $this->jwtGuard($guard, 'refresh token transport')->refreshTransport();
    }

    /**
     * Reset every package guard already resolved to the current request, as a
     * new HTTP request does, so nothing one unit of work bound (an identity, a
     * principal, a device) carries into the next: a queued job in a worker,
     * which keeps the application between jobs. Guards of other drivers are
     * left alone; no guard is created and no rebinding callback registered, as
     * `forgetGuards()` would on every job.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function forgetGuardState(): void
    {
        $request = $this->app->make('request');

        foreach ($this->guards as $guard) {

            if (!$guard instanceof AbstractGuard) {
                continue;
            }

            $guard->setRequest($request);
        }
    }

    /**
     * The active identity, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
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
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
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
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
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
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->tenant() : null;
    }

    /**
     * The active principal's type (its own, else its tenant's), when the active
     * guard is contextual and the principal has one.
     *
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function type(): ?string
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->type() : null;
    }

    /**
     * Resolve the named guard, or the default one, as a JWT guard, or fail
     * saying it has no such service.
     *
     * @param  ?string  $guard
     * @param  string  $service
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \InvalidArgumentException
     */
    private function jwtGuard(?string $guard, string $service): JwtGuard
    {
        $resolved = $this->guard($guard);

        if (!$resolved instanceof JwtGuard) {
            throw new \InvalidArgumentException(sprintf('Auth guard [%s] is not a jwt guard, so it has no %s.', $guard ?? $this->getDefaultDriver(), $service));
        }

        return $resolved;
    }
}
