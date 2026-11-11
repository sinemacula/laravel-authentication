<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\CallerCredentials;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContexts;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
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
use SineMacula\Laravel\Authentication\Support\ClosureRebinding;

/**
 * Laravel's auth manager with the package's contextual accessors and per-guard
 * services.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @inheritable
 */
class AuthManager extends IlluminateAuthManager
{
    /**
     * Take over the creators, user resolver and resolved guards of the manager
     * this one replaces in the `auth` binding.
     *
     * Closures bound to the replaced manager are rebound to this one, as
     * Laravel binds `viaRequest()` and anonymous `extend()` closures.
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
            $this->customCreators[$driver] = ClosureRebinding::onto($replaced, $this, $creator);
        }

        /** @var array<string, \Closure(): mixed> $providerCreators */
        $providerCreators = $replaced->customProviderCreators;

        foreach ($providerCreators as $driver => $creator) {
            $this->customProviderCreators[$driver] = ClosureRebinding::onto($replaced, $this, $creator);
        }

        $this->guards       = $replaced->guards;
        $this->userResolver = ClosureRebinding::onto($replaced, $this, $replaced->userResolver);
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
     * Return the session service of the named JWT guard, or of the default
     * guard.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function sessions(?string $guard = null): SessionService
    {
        $resolved = JwtGuard::from($this, $guard, 'session service');
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
     * Return the names of the `jwt` guards, which keep sessions, unresolved.
     *
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function sessionGuards(): array
    {
        return JwtGuards::names($this->app->make(Repository::class));
    }

    /**
     * Return the one-time code service of the named JWT guard, or of the
     * default guard.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Codes\CodeService
     *
     * @throws \InvalidArgumentException
     */
    public function codes(?string $guard = null): CodeService
    {
        return new CodeService(JwtGuard::from($this, $guard, 'one-time code service')->context(), $this->app);
    }

    /**
     * Return the password service of the named JWT guard, or of the default
     * guard.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function passwords(?string $guard = null): PasswordService
    {
        $context = JwtGuard::from($this, $guard, 'password service')->context();

        return new PasswordService($context, SessionRevocations::forContext($context, $this->app), $this->app);
    }

    /**
     * Return the refresh token transport of the named JWT guard, or of the
     * default guard.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     *
     * @throws \InvalidArgumentException
     */
    public function refreshTransport(?string $guard = null): RefreshTokenTransport
    {
        return JwtGuard::from($this, $guard, 'refresh token transport')->refreshTransport();
    }

    /**
     * Return the passkey service of the named JWT guard, or of the default
     * guard.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyService
     *
     * @throws \InvalidArgumentException
     */
    public function passkeys(?string $guard = null): PasskeyService
    {
        return new PasskeyService(JwtGuard::from($this, $guard, 'passkey service')->context(), $this->app);
    }

    /**
     * Return the identifier change service of the named JWT guard, or of the
     * default guard.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService
     *
     * @throws \InvalidArgumentException
     */
    public function identifierChanges(?string $guard = null): IdentifierChangeService
    {
        return new IdentifierChangeService(JwtGuard::from($this, $guard, 'identifier change service')->context(), $this->app);
    }

    /**
     * Return the API key service of the named `api_key` or `jwt` guard, or of
     * the default guard.
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
     * default guard.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange
     *
     * @throws \InvalidArgumentException
     */
    public function clientCredentials(?string $guard = null): ClientCredentialsExchange
    {
        return new ClientCredentialsExchange(JwtGuard::from($this, $guard, 'client credentials exchange')->context(), $this->app);
    }

    /**
     * Return the caller the current request's credential proves, or `null`.
     *
     * @return ?\SineMacula\Laravel\Authentication\Callers\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function caller(): ?Caller
    {
        /** @var \Illuminate\Http\Request $request */
        $request = $this->app->make('request');

        $callers = new CallerCredentials($this, $this->app->make(Repository::class), $this->app->make(Dispatcher::class));

        return $callers->caller($request);
    }

    /**
     * Reset every resolved package guard to the current request, so nothing one
     * queued job bound carries into the next.
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
     * The named package guard if it is already resolved, without creating it.
     *
     * @param  string  $name
     * @return (\SineMacula\Laravel\Authentication\Contracts\ContextualGuard&\SineMacula\Laravel\Authentication\Contracts\GuardBinding)|null
     *
     * @internal
     */
    public function resolvedGuard(string $name): (ContextualGuard&GuardBinding)|null
    {
        $guard = $this->guards[$name] ?? null;

        return $guard instanceof AbstractGuard ? $guard : null;
    }

    /**
     * The authentication context of the current request, or `null` for a guest.
     *
     * @return ?\SineMacula\Laravel\Authentication\Context\AuthenticationContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function context(): ?AuthenticationContext
    {
        return $this->app->make(AuthenticationContexts::class)->current();
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
     * The active session, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function session(): ?Session
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->session() : null;
    }

    /**
     * The active tenant, when the active guard is contextual.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant
    {
        $guard = $this->guard();

        return $guard instanceof ContextualGuard ? $guard->tenant() : null;
    }

    /**
     * The scopes the request's credential grants; `null` for a human session.
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
}
