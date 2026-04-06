<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use InvalidArgumentException;
use SensitiveParameter;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;

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
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
abstract class AbstractGuard implements ContextualGuard
{
    /** @var \SineMacula\Laravel\Authentication\Contracts\Identity|null The identity currently bound to the guard, if any. */
    protected ?Identity $identity = null;

    /** @var \SineMacula\Laravel\Authentication\Contracts\Principal|null The principal currently bound to the guard, if any. */
    protected ?Principal $principal = null;

    /** @var \SineMacula\Laravel\Authentication\Contracts\Device|null The device currently bound to the guard, if any. */
    protected ?Device $device = null;

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
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Determine if the current request has no authenticated identity.
     *
     * @return bool
     */
    public function guest(): bool
    {
        return ! $this->check();
    }

    /**
     * Return the authenticated identity bound to the guard, if any.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    public function user(): ?Identity
    {
        return $this->identity;
    }

    /**
     * Return the auth identifier of the bound identity, if any.
     *
     * @return int|string|null
     */
    public function id(): int|string|null
    {
        $identifier = $this->identity?->getAuthIdentifier();

        if ($identifier === null || is_int($identifier) || is_string($identifier)) {
            return $identifier;
        }

        return (string) $identifier;
    }

    /**
     * Validate the supplied credentials against the identity provider
     * without mutating the guard's state.
     *
     * @param  array<array-key, mixed> $credentials The credentials to validate.
     * @return bool
     */
    public function validate(#[SensitiveParameter] array $credentials = []): bool
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
    public function hasUser(): bool
    {
        return $this->identity !== null;
    }

    /**
     * Bind an authenticated identity to the guard.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user The identity to bind.
     * @return $this
     *
     * @throws \InvalidArgumentException When the supplied `Authenticatable` is not an `Identity`.
     */
    public function setUser(Authenticatable $user): self
    {
        if (! $user instanceof Identity) {
            throw new InvalidArgumentException(sprintf(
                'Guard %s expected an Identity instance, got %s.',
                $this->name,
                $user::class,
            ));
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
     * @param  array<string, mixed>                                        $credentials The credentials to authenticate with.
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal|null $principal   Optional principal override; when null the resolver derives it.
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device|null    $device      Optional device to pin to the guard on success.
     * @return bool
     */
    public function attempt(#[SensitiveParameter] array $credentials, ?Principal $principal = null, ?Device $device = null): bool
    {
        $this->fireAttemptingEvent($credentials);

        $user = $this->provider->retrieveByCredentials($credentials);

        if ($user !== null && $this->hasValidCredentials($user, $credentials) && $user instanceof Identity) {

            $resolvedPrincipal = $principal ?? $this->resolver->resolve($user);

            if ($resolvedPrincipal === null) {
                $this->fireFailedEvent($user, $credentials);

                return false;
            }

            $this->login($user, $resolvedPrincipal, $device);

            return true;
        }

        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    /**
     * Bind a fully resolved identity, principal, and optional device to
     * the guard, firing the standard Laravel `Login` event on completion.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity   $identity  The authenticated identity.
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal The principal acting on behalf of the identity.
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device|null $device   Optional device to pin to the guard.
     * @return void
     */
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void
    {
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

        $this->identity  = null;
        $this->principal = null;
        $this->device    = null;
    }

    /**
     * Return the authenticated identity, if any.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    public function identity(): ?Identity
    {
        return $this->identity;
    }

    /**
     * Return the active principal, if any.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|null
     */
    public function principal(): ?Principal
    {
        return $this->principal;
    }

    /**
     * Return the pinned device, if any.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Device|null
     */
    public function device(): ?Device
    {
        return $this->device;
    }

    /**
     * Return the organization the active principal acts within, if any.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Organization|null
     */
    public function organization(): ?Organization
    {
        return $this->principal?->getOrganization();
    }

    /**
     * Return the active organization scope string, if any.
     *
     * @return string|null
     */
    public function scope(): ?string
    {
        return $this->organization()?->getOrganizationScope();
    }

    /**
     * Determine whether the active scope matches the configured
     * internal scope string.
     *
     * @return bool
     */
    public function isInternal(): bool
    {
        $internal = (string) config('laravel-authentication.scopes.internal', 'internal');

        return $this->scope() === $internal;
    }

    /**
     * Determine whether the active scope matches the configured
     * external scope string.
     *
     * @return bool
     */
    public function isExternal(): bool
    {
        $external = (string) config('laravel-authentication.scopes.external', 'external');

        return $this->scope() === $external;
    }

    /**
     * Pin the active principal for the current request and fire
     * the `PrincipalAssigned` custom event.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal $principal The principal to bind.
     * @return static
     */
    public function setPrincipal(Principal $principal): static
    {
        $this->principal = $principal;

        $this->events->dispatch(new PrincipalAssigned($this->name, $principal));

        return $this;
    }

    /**
     * Pin the active device for the current request and fire
     * the `DeviceAuthenticated` custom event.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device $device The device to bind.
     * @return static
     */
    public function setDevice(Device $device): static
    {
        $this->device = $device;

        $this->events->dispatch(new DeviceAuthenticated($this->name, $device));

        return $this;
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
     * @param  \Illuminate\Http\Request $request The request to bind.
     * @return static
     */
    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    // -----------------------------------------------------------------
    //  Helpers used by subclasses
    // -----------------------------------------------------------------

    /**
     * Bind an identity to the guard and fire the standard Laravel
     * `Authenticated` event. Shared entry point for `setUser()` and
     * the contextual `login()` path.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity $identity The identity to bind.
     * @return void
     */
    protected function setIdentity(Identity $identity): void
    {
        $this->identity = $identity;

        $this->events->dispatch(new Authenticated($this->name, $identity));
    }

    /**
     * Timing-safe credential validation.
     *
     * Wraps the hasher check inside `Timebox::call()` so the call site
     * takes the same elapsed time regardless of whether the supplied
     * identifier resolved to a persisted user (NFR-04). The `Validated`
     * standard event is fired from inside the timebox so subscribers
     * still observe a successful hasher check.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null $user        The user resolved from the identifier, if any.
     * @param  array<string, mixed>                            $credentials The credentials supplied with the attempt.
     * @return bool
     */
    protected function hasValidCredentials(?Authenticatable $user, #[SensitiveParameter] array $credentials): bool
    {
        return $this->timebox->call(function () use ($user, $credentials): bool {

            $valid = $user !== null && $this->provider->validateCredentials($user, $credentials);

            if ($valid) {
                $this->fireValidatedEvent($user);
            }

            return $valid;
        }, 200_000);
    }

    /**
     * Fire the standard Laravel `Attempting` event.
     *
     * @param  array<string, mixed> $credentials The credentials supplied with the attempt.
     * @return void
     */
    protected function fireAttemptingEvent(#[SensitiveParameter] array $credentials): void
    {
        $this->events->dispatch(new Attempting($this->name, $credentials, false));
    }

    /**
     * Fire the standard Laravel `Validated` event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user The user whose credentials were validated.
     * @return void
     */
    protected function fireValidatedEvent(Authenticatable $user): void
    {
        $this->events->dispatch(new Validated($this->name, $user));
    }

    /**
     * Fire the standard Laravel `Failed` event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null $user        The resolved user, if any.
     * @param  array<string, mixed>                            $credentials The credentials supplied with the attempt.
     * @return void
     */
    protected function fireFailedEvent(?Authenticatable $user, #[SensitiveParameter] array $credentials): void
    {
        $this->events->dispatch(new Failed($this->name, $user, $credentials));
    }
}
