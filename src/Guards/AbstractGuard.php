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

    /** @var \Illuminate\Contracts\Auth\Authenticatable|null Last user retrieved by `resolveContextForCredentials()`, kept so the failure path can include it on the `Failed` event. */
    private ?Authenticatable $lastRetrievedUser = null;

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
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validate(#[\SensitiveParameter] array $credentials = []): bool
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        if ($user === null) {
            return false;
        }

        return $this->hasValidCredentials($user, $credentials);
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

        $this->fireAttemptingEvent($credentials);

        $resolved = $this->resolveContextForCredentials($credentials, $principal);

        if ($resolved === null) {
            $this->fireFailedEvent($this->lastRetrievedUser, $credentials);

            return false;
        }

        [$identity, $resolvedPrincipal] = $resolved;

        $this->login($identity, $resolvedPrincipal, $device);

        return true;
    }

    /**
     * Bind a fully resolved identity, principal, and optional device to
     * the guard, firing the standard Laravel `Login` event on completion.
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
        $this->clearContextualState();

        $this->setIdentity($identity);
        $this->setPrincipal($principal);

        if ($device !== null) {
            $this->setDevice($device);
        }

        $this->events->dispatch(new Login($this->name, $identity, false));
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

        $credentialsValid = $user !== null
            && $this->hasValidCredentials($user, $credentials)
            && $user instanceof Identity
            && $this->isIdentityActive($user);

        if (!$credentialsValid) {
            return null;
        }

        /** @var \SineMacula\Laravel\Authentication\Contracts\Identity $user */
        $resolved = $principal ?? $this->resolver->resolve($user);

        if ($resolved === null || !$resolved->isActive()) {
            return null;
        }

        return [$user, $resolved];
    }
}
