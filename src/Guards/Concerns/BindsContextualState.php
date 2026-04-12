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
     * Return the authenticated identity, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    public function identity(): ?Identity
    {
        return $this->identity;
    }

    /**
     * Return the active principal, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function principal(): ?Principal
    {
        return $this->principal;
    }

    /**
     * Return the pinned device, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    public function device(): ?Device
    {
        return $this->device;
    }

    /**
     * Return the active tenant's type string, if the tenant declares the
     * `HasType` capability.
     *
     * @return ?string
     */
    public function type(): ?string
    {
        $tenant = $this->tenant();

        return $tenant instanceof HasType ? $tenant->getType() : null;
    }

    /**
     * Return the tenant the active principal acts within, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    public function tenant(): ?Tenant
    {
        return $this->principal?->getTenant();
    }

    /**
     * Pin the active principal for the current request and fire the
     * `PrincipalAssigned` custom event.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return static
     */
    public function setPrincipal(Principal $principal): static
    {
        $this->principal = $principal;

        $this->dispatcher()->dispatch(new PrincipalAssigned($this->name, $principal));

        return $this;
    }

    /**
     * Pin the active device for the current request and fire the
     * `DeviceAuthenticated` custom event.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return static
     */
    public function setDevice(Device $device): static
    {
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
