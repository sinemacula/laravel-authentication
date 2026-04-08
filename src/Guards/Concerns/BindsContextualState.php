<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;

/**
 * Holds the identity → principal → device contextual triple bound to
 * a guard instance and exposes the read-side accessors plus the
 * principal/device setters that fire the package's custom contextual
 * events.
 *
 * Used by `AbstractGuard` so the contextual surface is decomposed
 * away from the credential-validation and Laravel-contract surface.
 *
 * Expects the using class to declare:
 * - `protected string $name` (the registered guard name)
 * - `protected \Illuminate\Contracts\Events\Dispatcher $events`
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
 *
 * @property string $name
 * @property \Illuminate\Contracts\Events\Dispatcher $events
 */
trait BindsContextualState
{
    /** @var \SineMacula\Laravel\Authentication\Contracts\Identity|null Identity bound to the guard, if any. */
    protected ?Identity $identity = null;

    /** @var \SineMacula\Laravel\Authentication\Contracts\Principal|null Principal bound to the guard, if any. */
    protected ?Principal $principal = null;

    /** @var \SineMacula\Laravel\Authentication\Contracts\Device|null Device bound to the guard, if any. */
    protected ?Device $device = null;

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
        return $this->scope() === Config::string('laravel-authentication.scopes.internal', 'internal');
    }

    /**
     * Determine whether the active scope matches the configured
     * external scope string.
     *
     * @return bool
     */
    public function isExternal(): bool
    {
        return $this->scope() === Config::string('laravel-authentication.scopes.external', 'external');
    }

    /**
     * Pin the active principal for the current request and fire
     * the `PrincipalAssigned` custom event.
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
     * Pin the active device for the current request and fire
     * the `DeviceAuthenticated` custom event.
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
     * Clear identity, principal, and device state without firing any
     * events. Used by `login()` and `logout()` — the caller is
     * responsible for any event dispatch.
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
     * Return the host class's event dispatcher. Centralised so the
     * trait does not have to repeat the `$this->events` access path.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    private function dispatcher(): Dispatcher
    {
        return $this->events;
    }
}
