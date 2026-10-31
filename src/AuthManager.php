<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Package AuthManager.
 *
 * Subclass of Laravel's `AuthManager` that exposes the contextual accessors
 * (`identity`, `principal`, `device`, `tenant`, `type`, `scopes`), guard-scoped
 * `jwt()` issuance, each JWT guard's `sessions()`, `codes()`, `passwords()`,
 * `passkeys()`, `identifierChanges()`, `refreshTransport()` and
 * `clientCredentials()`, and the API keys of an `api_key` or JWT guard
 * (`apiKeys()`) directly on the manager. Each contextual accessor forwards to
 * the active guard when it implements `ContextualGuard`, otherwise returns
 * `null`. Bound to the `auth` container key by `AuthenticationServiceProvider`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @inheritable
 */
class AuthManager extends IlluminateAuthManager
{
    /**
     * Take over the state of the framework manager this one replaces in the
     * `auth` binding, so what the application or another package set on it
     * before the package booted keeps working: its guard creators
     * (`Auth::extend()`, `Auth::viaRequest()`), its user provider creators
     * (`Auth::provider()`), its user resolver (`resolveUsersUsing()`), and the
     * guards it has already resolved, which stay the same instances.
     *
     * An anonymous closure bound to the replaced manager (`viaRequest()` binds
     * its creator, Laravel 13 binds each anonymous `extend()` closure, and the
     * default user resolver is the manager's own) is bound to this one instead,
     * so the guards and user providers it reaches are this manager's; any other
     * closure is taken as it is.
     *
     * The replaced manager's own behaviour is not carried: the methods and
     * properties a subclass of Laravel's manager adds are lost, and so is
     * anything its closures rely on them for. The package owns the `auth`
     * binding: a manager of the application's extends this one, and the
     * provider then keeps it.
     *
     * @param  \Illuminate\Auth\AuthManager  $replaced
     * @return void
     *
     * @internal
     */
    public function inheritStateFrom(IlluminateAuthManager $replaced): void
    {
        /** @var array<string, \Closure(): mixed> $creators */
        $creators = $replaced->customCreators;

        foreach ($creators as $driver => $creator) {
            $this->customCreators[$driver] = $this->rebindFrom($replaced, $creator);
        }

        /** @var array<string, \Closure(): mixed> $providerCreators */
        $providerCreators = $replaced->customProviderCreators;

        foreach ($providerCreators as $driver => $creator) {
            $this->customProviderCreators[$driver] = $this->rebindFrom($replaced, $creator);
        }

        $this->guards       = $replaced->guards;
        $this->userResolver = $this->rebindFrom($replaced, $replaced->userResolver);
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
     * default guard when the name is omitted: built on each call, on the
     * guard's context and token service, with the guard as the binding its
     * sign-ins and refreshes bind, on the container's database connections and
     * transactions manager. It holds nothing between calls and reads the
     * context each time, so one handed out earlier follows the guard's rebinds
     * as a new one would.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function sessions(?string $guard = null): SessionService
    {
        $resolved = $this->jwtGuard($guard, 'session service');
        $app      = $this->app;

        return new SessionService(
            $resolved->context(),
            $resolved,
            $resolved->tokens(),
            $app,
            $app->make(ConnectionResolverInterface::class),
            static fn (): mixed => $app->bound('db.transactions') ? $app->make('db.transactions') : null,
        );
    }

    /**
     * Return the one-time code service of the named JWT guard, or of the
     * current default guard when the name is omitted, to send sign-in codes and
     * to verify identifiers by code.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Codes\CodeService
     *
     * @throws \InvalidArgumentException
     */
    public function codes(?string $guard = null): CodeService
    {
        return new CodeService($this->jwtGuard($guard, 'one-time code service')->context(), $this->app);
    }

    /**
     * Return the password service of the named JWT guard, or of the current
     * default guard when the name is omitted: the password policy, and setting
     * a password at a registration, a change or a reset.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function passwords(?string $guard = null): PasswordService
    {
        $context = $this->jwtGuard($guard, 'password service')->context();

        return new PasswordService($context, SessionRevocations::forContext($context, $this->app), $this->app);
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
     * Return the passkey service of the named JWT guard, or of the current
     * default guard when the name is omitted: its registration, sign-in and
     * factor ceremonies, and the listing and removal of an identity's passkeys,
     * for the guard's relying party.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyService
     *
     * @throws \InvalidArgumentException
     */
    public function passkeys(?string $guard = null): PasskeyService
    {
        return new PasskeyService($this->jwtGuard($guard, 'passkey service')->context(), $this->app);
    }

    /**
     * Return the identifier change service of the named JWT guard, or of the
     * current default guard when the name is omitted, to change an identity's
     * email address or phone number once the new one is proven.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService
     *
     * @throws \InvalidArgumentException
     */
    public function identifierChanges(?string $guard = null): IdentifierChangeService
    {
        return new IdentifierChangeService($this->jwtGuard($guard, 'identifier change service')->context(), $this->app);
    }

    /**
     * Return the API keys of the named guard, or of the current default guard
     * when the name is omitted: an `api_key` guard, whose requests present
     * them, or a `jwt` guard, whose client credentials exchange takes them.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService
     *
     * @throws \InvalidArgumentException
     */
    public function apiKeys(?string $guard = null): ApiKeyService
    {
        $resolved = $this->guard($guard);

        if (!$resolved instanceof ApiKeyGuard && !$resolved instanceof JwtGuard) {
            throw new \InvalidArgumentException(sprintf('Auth guard [%s] is neither an api_key nor a jwt guard, so it has no API keys.', $guard ?? $this->getDefaultDriver()));
        }

        return new ApiKeyService($resolved->context(), $this->app);
    }

    /**
     * Return the client credentials exchange of the named JWT guard, or of the
     * current default guard when the name is omitted, which exchanges an API
     * key, as an OAuth client's id and secret, for an access token of the
     * guard.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange
     *
     * @throws \InvalidArgumentException
     */
    public function clientCredentials(?string $guard = null): ClientCredentialsExchange
    {
        return new ClientCredentialsExchange($this->jwtGuard($guard, 'client credentials exchange')->context(), $this->app);
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
     * The scopes the active request's credential grants, when the active guard
     * is contextual: `null` for a human identity's session, which no credential
     * limits (and when the guard is not contextual), otherwise the granted
     * list.
     *
     * @return ?list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function scopes(): ?array
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->scopes() : null;
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

    /**
     * The closure, bound to this manager when it is an anonymous one bound to
     * the replaced manager; any other is returned as it is (a first-class
     * callable keeps the object whose method it is).
     *
     * @param  \Illuminate\Auth\AuthManager  $replaced
     * @param  \Closure(): mixed  $closure
     * @return \Closure(): mixed
     */
    private function rebindFrom(IlluminateAuthManager $replaced, \Closure $closure): \Closure
    {
        $reflector = new \ReflectionFunction($closure);

        if (!$reflector->isAnonymous() || $reflector->getClosureThis() !== $replaced) {
            return $closure;
        }

        $rebound = $closure->bindTo($this);

        assert($rebound instanceof \Closure);

        return $rebound;
    }
}
