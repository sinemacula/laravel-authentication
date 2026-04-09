<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;
use SineMacula\Laravel\Authentication\Guards\Concerns\ValidatesGuardCredentials;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Abstract base for the package's stateless contextual guards.
 *
 * Owns the contextual authentication lifecycle, standard and custom event
 * firing, timing-safe credential validation, and Laravel `Guard` contract
 * conformance. Concrete subclasses provide payload extraction and call
 * `attempt()`/`login()` to bind the resolved context.
 *
 * Contextual binding is composed via `BindsContextualState`;
 * credential-validation primitives via `ValidatesGuardCredentials`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
abstract class AbstractGuard implements ContextualGuard
{
    use BindsContextualState, ValidatesGuardCredentials;

    /** @var \Illuminate\Contracts\Auth\Authenticatable|null Last retrieved user; attached to the `Failed` event. */
    protected ?Authenticatable $lastRetrievedUser = null;

    /**
     * Constructor.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Support\Timebox  $timebox
     */
    public function __construct(

        /** Guard name, as registered under `auth.guards.<name>`. */
        protected string $name,

        /** Identity provider used to look up and validate credentials. */
        protected IdentityProvider $provider,

        /** Resolver that maps an identity to its acting principal. */
        protected PrincipalResolver $resolver,

        /** Event dispatcher for standard and custom auth events. */
        protected Dispatcher $events,

        /** Current HTTP request used to extract credentials. */
        protected Request $request,

        /** Timebox enforcing uniform elapsed time on the credential path. */
        protected Timebox $timebox,

    ) {}

    /**
     * Determine if the current request has no authenticated identity.
     *
     * @return bool
     */
    #[\Override]
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * Determine if the current request has an authenticated identity.
     *
     * @return bool
     */
    #[\Override]
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Return the authenticated identity bound to the guard, if any.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    #[\Override]
    public function user(): ?Identity
    {
        return $this->identity;
    }

    /**
     * Return the auth identifier of the bound identity, if any.
     *
     * @return int|string|null
     */
    #[\Override]
    public function id(): int|string|null
    {
        $identifier = $this->identity?->getAuthIdentifier();

        if ($identifier === null || is_int($identifier) || is_string($identifier)) {
            return $identifier;
        }

        return null;
    }

    /**
     * Validate credentials without mutating guard state.
     *
     * Wraps the whole retrieve -> validate pipeline in a single
     * `Timebox::call()` so elapsed time is uniform regardless of whether the
     * identifier resolves; preserves the timing-safety guarantee against
     * user-enumeration.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validate(#[\SensitiveParameter] array $credentials = []): bool
    {
        return $this->timebox->call(function (Timebox $timebox) use ($credentials): bool {

            $user = $this->provider->retrieveByCredentials($credentials);

            if ($this->hasValidCredentials($user, $credentials)) {
                $timebox->returnEarly();

                return true;
            }

            return false;
        }, $this->timeboxMicroseconds());
    }

    /**
     * Determine whether an identity is currently bound to the guard.
     *
     * @return bool
     */
    #[\Override]
    public function hasUser(): bool
    {
        return $this->identity !== null;
    }

    /**
     * Bind an authenticated identity to the guard.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return $this
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function setUser(Authenticatable $user): self
    {
        if (!$user instanceof Identity) {
            throw new \InvalidArgumentException(sprintf('Guard %s expected an Identity instance, got %s.', $this->name, $user::class));
        }

        $this->setIdentity($user);

        return $this;
    }

    /**
     * Attempt to authenticate a request against the identity provider,
     * optionally pinning a specific principal and device on success.
     *
     * @param  array<string, mixed>  $credentials
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal|null  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device|null  $device
     * @return bool
     */
    #[\Override]
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Device $device = null): bool
    {
        return $this->timebox->call(function (Timebox $timebox) use ($credentials, $principal, $device): bool {

            $this->fireAttemptingEvent($credentials);

            $resolved = $this->resolveContextForCredentials($credentials, $principal);

            if ($resolved === null) {
                $this->fireFailedEvent($this->lastRetrievedUser, $credentials);

                return false;
            }

            [$identity, $resolvedPrincipal] = $resolved;

            // attempt() bypasses login() because Validated already fired from
            // hasValidCredentials() - calling login() here would
            // double-dispatch.
            $this->bindAuthenticationLifecycle($identity, $resolvedPrincipal, $device);

            $timebox->returnEarly();

            return true;
        }, $this->timeboxMicroseconds());
    }

    /**
     * Bind a fully resolved identity, principal, and optional device, firing
     * `Validated` and `Login` around the bind.
     *
     * Public entry point for callers that validated the identity out-of-band
     * (refresh, OAuth, SSO, test helpers). Subclass `user()` paths that did NOT
     * go through `hasValidCredentials()` should call this so they pick up
     * `Validated` for free; paths that did should call
     * `bindAuthenticationLifecycle()` directly to avoid the double-fire.
     *
     * Any previously bound state is cleared first so callers cannot
     * inherit a stale device from a prior login on the same instance.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device|null  $device
     * @return void
     */
    #[\Override]
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void
    {
        $this->fireValidatedEvent($identity);

        $this->bindAuthenticationLifecycle($identity, $principal, $device);
    }

    /**
     * Clear all bound state and fire the standard Laravel `Logout` event when
     * an identity was previously bound.
     *
     * @return void
     */
    public function logout(): void
    {
        $identity = $this->identity;

        if ($identity !== null) {
            $this->events->dispatch(new Logout($this->name, $identity));
        }

        $this->clearContextualState();
    }

    /**
     * Return the registered name of this guard.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Rebind the current HTTP request onto the guard. Called by the service
     * provider on each container-resolve cycle.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return static
     */
    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Rebind the event dispatcher onto the guard, so test suites that swap it
     * after the guard is resolved (e.g. `Event::fake()`) get a fresh reference.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return static
     */
    public function setDispatcher(Dispatcher $events): static
    {
        $this->events = $events;

        return $this;
    }

    /**
     * Rebind the principal resolver, so consumers that swap it after guard
     * construction (test fakes, runtime tenancy switches) propagate the new
     * resolver into the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @return static
     */
    public function setPrincipalResolver(PrincipalResolver $resolver): static
    {
        $this->resolver = $resolver;

        return $this;
    }

    /**
     * Bind an identity to the guard and fire the standard Laravel
     * `Authenticated` event. Shared entry point for `setUser()` and the
     * contextual `login()` path.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return void
     */
    protected function setIdentity(Identity $identity): void
    {
        $this->identity = $identity;

        $this->events->dispatch(new Authenticated($this->name, $identity));
    }

    /**
     * Whether the identity opts into activation checking and, if it does,
     * whether it currently reports active. Returns `true` for identities that
     * do not implement `CanBeActive`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    protected function isIdentityActive(Identity $identity): bool
    {
        if (!$identity instanceof CanBeActive) {
            return true;
        }

        return $identity->isActive();
    }

    /**
     * Resolve a principal for the identity, catching
     * `UnresolvableIdentityException` and returning `null` so the calling auth
     * path surfaces a `Failed` event + 401 rather than propagating a 500.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|null
     */
    protected function safeResolvePrincipal(Identity $identity, mixed $hint = null): ?Principal
    {
        try {
            return $hint === null
                ? $this->resolver->resolve($identity)
                : $this->resolver->resolve($identity, $hint);
        } catch (UnresolvableIdentityException) {
            return null;
        }
    }

    /**
     * Internal bind: clear prior state, dispatch `Login`, then set the
     * contextual triple (which dispatches `Authenticated`, `PrincipalAssigned`,
     * and `DeviceAuthenticated` in order).
     *
     * The Login-before-Authenticated order mirrors Laravel's first-party
     * `SessionGuard::login()` so consumers see the same ordering regardless of
     * which guard they use.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device|null  $device
     * @return void
     */
    protected function bindAuthenticationLifecycle(Identity $identity, Principal $principal, ?Device $device = null): void
    {
        $this->clearContextualState();

        $this->events->dispatch(new Login($this->name, $identity, false));

        $this->setIdentity($identity);
        $this->setPrincipal($principal);

        if ($device !== null) {
            $this->setDevice($device);
        }
    }

    /**
     * Resolve the (identity, principal) pair for an `attempt()` call, or `null`
     * if any check fails. Stores the retrieved user on
     * `$this->lastRetrievedUser` so the caller can attribute the `Failed` event
     * without re-fetching.
     *
     * @formatter:off
     *
     * @param  array<string, mixed>  $credentials
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal|null  $principal
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}|null
     *
     * @formatter:on
     */
    private function resolveContextForCredentials(#[\SensitiveParameter] array $credentials, ?Principal $principal): ?array
    {
        $this->lastRetrievedUser = $this->provider->retrieveByCredentials($credentials);
        $user                    = $this->lastRetrievedUser;

        // `hasValidCredentials` is called unconditionally (even on a null user)
        // so elapsed time is uniform regardless of resolution; the trait
        // handles the null case internally.
        $credentialsAccepted = $this->hasValidCredentials($user, $credentials)
            && $user instanceof Identity
            && $this->isIdentityActive($user);

        if (!$credentialsAccepted) {
            return null;
        }

        /** @var \SineMacula\Laravel\Authentication\Contracts\Identity $user */
        $resolved = $principal ?? $this->safeResolvePrincipal($user);

        return $resolved !== null && $resolved->isActive() ? [$user, $resolved] : null;
    }
}
