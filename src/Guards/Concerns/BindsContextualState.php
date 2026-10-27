<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;

/**
 * Holds the identity -> principal -> device triple bound to a guard and exposes
 * accessors plus setters that fire the contextual events.
 *
 * Every accessor goes through the host guard's `user()`, so the first access on
 * a request resolves it, as Laravel's own guards do, even on a route without
 * authentication middleware.
 *
 * Expects the using class to declare:
 * - `protected string $name`
 * - `protected \Illuminate\Contracts\Events\Dispatcher $events`
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
 *
 * @property string $name
 * @property \Illuminate\Contracts\Events\Dispatcher $events
 */
trait BindsContextualState
{
    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Identity Identity bound to the guard, if any. */
    protected ?Identity $identity = null;

    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Principal Principal bound to the guard, if any. */
    protected ?Principal $principal = null;

    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Device Device bound to the guard, if any. */
    protected ?Device $device = null;

    /**
     * Return the authenticated identity, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function identity(): ?Identity
    {
        return $this->user();
    }

    /**
     * Return the active principal, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principal(): ?Principal
    {
        $this->user();

        return $this->principal;
    }

    /**
     * Return the pinned device, if any, resolving the request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function device(): ?Device
    {
        $this->user();

        return $this->device;
    }

    /**
     * Return the active tenant's type string, if the tenant declares the
     * `HasType` capability, resolving the request on first access.
     *
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function type(): ?string
    {
        $tenant = $this->tenant();

        return $tenant instanceof HasType ? $tenant->getType() : null;
    }

    /**
     * Return the tenant the active principal acts within, if any, resolving the
     * request on first access.
     *
     * Throws `TenantUnavailableException` when the principal names a tenant
     * that opts into activation but cannot be loaded. The authentication paths
     * reject such a principal, so this is reached only for one bound through
     * the trusted `login()` or `setUser()`, or a tenant deleted since.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant
    {
        return $this->principal()?->getTenant();
    }

    /**
     * Pin the active principal for the current request and fire the
     * `PrincipalAssigned` custom event.
     *
     * The request is resolved first, so the pin replaces the principal the
     * request's credential binds instead of being replaced by it on the next
     * access.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return static
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setPrincipal(Principal $principal): static
    {
        $this->user();

        $this->principal = $principal;

        $this->dispatcher()->dispatch(new PrincipalAssigned($this->name, $principal));

        return $this;
    }

    /**
     * Pin the active device for the current request and fire the
     * `DeviceAuthenticated` custom event.
     *
     * The request is resolved first, so the pin replaces the device the
     * request's credential binds instead of being replaced by it on the next
     * access.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return static
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setDevice(Device $device): static
    {
        $this->user();

        $this->device = $device;

        $this->dispatcher()->dispatch(new DeviceAuthenticated($this->name, $device));

        return $this;
    }

    /**
     * Clear identity, principal, and device state without firing events. The
     * caller dispatches any events.
     *
     * @return void
     */
    protected function clearContextualState(): void
    {
        $this->identity  = null;
        $this->principal = null;
        $this->device    = null;
    }

    /**
     * Return the host class's event dispatcher.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    private function dispatcher(): Dispatcher
    {
        return $this->events;
    }
}
