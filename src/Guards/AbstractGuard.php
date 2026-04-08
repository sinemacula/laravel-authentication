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
 * Owns the contextual authentication lifecycle (identity, principal,
 * device, organization), standard and custom event firing, timing-safe
 * credential validation, and Laravel `Guard` contract conformance.
 *
 * Concrete subclasses (`JwtGuard`, `BasicGuard`) provide payload
 * extraction and call into `attempt()`/`login()` to bind the resolved
 * context.
 *
 * The contextual binding surface (identity/principal/device accessors,
 * organization scope helpers) is composed in via the
 * `BindsContextualState` trait. The credential-validation primitives
 * (timebox, standard `Attempting` / `Validated` / `Failed` event
 * firing) are composed in via the `ValidatesGuardCredentials` trait.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
abstract class AbstractGuard implements ContextualGuard
{
    use BindsContextualState;
    use ValidatesGuardCredentials;

    // -----------------------------------------------------------------
    //  Helpers used by subclasses
    // -----------------------------------------------------------------

    /**
     * @var \Illuminate\Contracts\Auth\Authenticatable|null last user retrieved by `resolveContextForCredentials()` or a
     *                                                      subclass's bearer-resolution path, kept so the failure
     *                                                      branch can include it on the `Failed` event
     */
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

        /** Name of this guard as registered with Laravel's AuthManager. */
        protected string $name,

        /** Identity provider used to retrieve identities. */
        protected IdentityProvider $provider,

        /** Resolver used to derive a principal for the resolved identity. */
        protected PrincipalResolver $resolver,

        /** Event dispatcher used for both standard and custom events. */
        protected Dispatcher $events,

        /** Current request — refreshed on each rebind by the service provider. */
        protected Request $request,

        /** Timebox used to make credential validation constant-time. */
        protected Timebox $timebox,

    ) {}

    // -----------------------------------------------------------------
    //  Laravel Guard contract conformance
    // -----------------------------------------------------------------

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
     * Validate the supplied credentials against the identity provider
     * without mutating the guard's state.
     *
     * Wraps the entire `retrieveByCredentials` → `hasValidCredentials`
     * pipeline in a single `Timebox::call()` so the elapsed time is
     * uniform regardless of whether the supplied identifier resolves
     * to a persisted user — preserves the timing-safety guarantee
     * against user-enumeration attacks (NFR-04).
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

    // -----------------------------------------------------------------
    //  Contextual surface
    // -----------------------------------------------------------------

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
    public function attempt(
        #[\SensitiveParameter] array $credentials,
        ?Principal $principal = null,
        ?Device $device = null,
    ): bool {
        return $this->timebox->call(function (Timebox $timebox) use ($credentials, $principal, $device): bool {
            $this->fireAttemptingEvent($credentials);

            $resolved = $this->resolveContextForCredentials($credentials, $principal);

            if ($resolved === null) {
                $this->fireFailedEvent($this->lastRetrievedUser, $credentials);

                return false;
            }

            [$identity, $resolvedPrincipal] = $resolved;

            // attempt() bypasses the public login() because the
            // Validated event has already fired from inside
            // hasValidCredentials() — calling login() here would
            // double-dispatch.
            $this->bindAuthenticationLifecycle($identity, $resolvedPrincipal, $device);

            $timebox->returnEarly();

            return true;
        }, $this->timeboxMicroseconds());
    }

    /**
     * Bind a fully resolved identity, principal, and optional device to
     * the guard, firing the standard Laravel `Validated` and `Login`
     * events around the bind.
     *
     * Public entry point for callers that have validated the identity
     * out-of-band — refresh-token exchanges, OAuth callbacks, SSO
     * flows, test helpers — and now want to surface the bind through
     * the same event sequence the credential `attempt()` path emits.
     * Subclass `user()` paths that *did not* go through
     * `hasValidCredentials()` (notably the JWT bearer-token resolver)
     * should call this method so they pick up the `Validated` firing
     * for free; subclass paths that *did* go through
     * `hasValidCredentials()` (notably `BasicGuard::user()`) should
     * call `bindAuthenticationLifecycle()` directly to avoid the
     * double-fire.
     *
     * Any previously bound state (identity, principal, device) is
     * cleared first so callers cannot accidentally inherit a stale
     * device from a prior login on the same guard instance.
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
     * Clear all bound state and fire the standard Laravel `Logout`
     * event when an identity was previously bound.
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
     * Rebind the current HTTP request onto the guard. Called by the
     * service provider on each container-resolve cycle.
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
     * Rebind the event dispatcher onto the guard. Called by the
     * service provider via `$app->refresh('events', ...)` so test
     * suites that swap the dispatcher (e.g. via `Event::fake()`
     * after the guard has been resolved) get a fresh reference
     * instead of holding the original.
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
     * Rebind the principal resolver onto the guard. Called by the
     * service provider via `$app->refresh(PrincipalResolver::class,
     * ...)` so consumers that swap the resolver after guard
     * construction (test fakes, runtime tenancy switches) propagate
     * the new resolver into the guard.
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
     * Internal bind: clear any prior state, dispatch the standard
     * `Login` event, and then set the contextual triple (which
     * dispatches `Authenticated`, `PrincipalAssigned`, and
     * `DeviceAuthenticated` in that order).
     *
     * The Login-before-Authenticated order mirrors Laravel's
     * first-party `SessionGuard::login()` (it calls
     * `fireLoginEvent()` before `setUser()`, and `setUser()` is
     * where `Authenticated` fires from). Consumers listening to
     * the standard Laravel auth events therefore see the exact
     * same ordering whether they use a package guard or the
     * framework's session guard.
     *
     * Used by both `attempt()` (which already fired `Validated`
     * via `hasValidCredentials`) and `login()` (which fires
     * `Validated` itself before calling this helper).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device|null  $device
     * @return void
     */
    protected function bindAuthenticationLifecycle(
        Identity $identity,
        Principal $principal,
        ?Device $device = null,
    ): void {
        $this->clearContextualState();

        $this->events->dispatch(new Login($this->name, $identity, false));

        $this->setIdentity($identity);
        $this->setPrincipal($principal);

        if ($device !== null) {
            $this->setDevice($device);
        }
    }

    /**
     * Bind an identity to the guard and fire the standard Laravel
     * `Authenticated` event. Shared entry point for `setUser()` and
     * the contextual `login()` path.
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
     * Whether the supplied identity opts into activation checking and,
     * if it does, whether it currently reports itself active. Returns
     * `true` for identities that do not implement `CanBeActive` so
     * legacy consumers without the capability contract are unchanged.
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
     * Resolve a principal for the supplied identity, catching the
     * typed `UnresolvableIdentityException` thrown by the package's
     * default resolver when an identity implements neither `Principal`
     * nor `HasPrincipals`. The exception is converted into a `null`
     * return so the calling auth path surfaces a `Failed` event +
     * 401 response rather than propagating a 500 to the consumer.
     *
     * Subclass guards (`JwtGuard`) call this helper from their own
     * `user()` and `refresh()` paths so the misconfigured-identity
     * surface is handled consistently.
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
     * Resolve the (identity, principal) pair for an `attempt()` call,
     * or `null` if any check fails.
     *
     * Single-return helper extracted so `attempt()` itself stays
     * within the project's branch-count threshold. Stores the
     * retrieved user on `$this->lastRetrievedUser` so the caller can
     * include it on the `Failed` event without re-fetching.
     *
     * @param  array<string, mixed>  $credentials
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal|null  $principal
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}|null
     */
    private function resolveContextForCredentials(
        #[\SensitiveParameter] array $credentials,
        ?Principal $principal,
    ): ?array {

        $this->lastRetrievedUser = $this->provider->retrieveByCredentials($credentials);
        $user                    = $this->lastRetrievedUser;

        // `hasValidCredentials` is called unconditionally (even on a
        // null user) so the elapsed time is uniform regardless of
        // whether the supplied identifier resolved. The trait's
        // implementation handles the null case internally and the
        // enclosing `attempt()` timebox absorbs the whole pipeline.
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
