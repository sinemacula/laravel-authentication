<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\Authentication\Audience\PrincipalType;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Holds the identity -> principal -> device triple bound to a guard, with the
 * credential that authenticated it and the scopes that credential grants, and
 * exposes accessors plus setters that fire the contextual events. Each event
 * carries the whole bound context, set before it is dispatched, with the
 * request's client.
 *
 * Every accessor goes through the host guard's `user()`, so the first access on
 * a request resolves it, as Laravel's own guards do, even on a route without
 * authentication middleware.
 *
 * Expects the using class to declare:
 * - `protected string $name`
 * - `protected \Illuminate\Contracts\Events\Dispatcher $events`
 * - `protected \Illuminate\Http\Request $request`
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
 *
 * @property string $name
 * @property \Illuminate\Contracts\Events\Dispatcher $events
 * @property \Illuminate\Http\Request $request
 */
trait BindsContextualState
{
    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Identity Identity bound to the guard, if any. */
    protected ?Identity $identity = null;

    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Principal Principal bound to the guard, if any. */
    protected ?Principal $principal = null;

    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Device Device bound to the guard, if any. */
    protected ?Device $device = null;

    /** @var ?string Identifier of the credential (an API key) that authenticated the bound identity, if any. */
    protected ?string $credentialId = null;

    /** @var ?list<string> Scopes the bound context is limited to; `null` when no credential limits it. */
    protected ?array $scopes = null;

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
     * Return the scopes the request's credential grants, resolving the request
     * on first access: `null` for a human identity's session, which no
     * credential limits, and the granted list (`[]` for none) for an API key or
     * a client-credentials token. A non-human identity bound without a
     * credential (through the trusted `login()`, `setUser()` or
     * `authenticateAs()`) gets `[]`: a machine is always limited. The package
     * carries scopes and never interprets them; they are a ceiling the
     * application's authorization intersects with the principal's permissions.
     *
     * @return ?list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function scopes(): ?array
    {
        $this->user();

        return $this->scopes;
    }

    /**
     * Return the active principal's type, if any, resolving the request on
     * first access: the principal's own type when it declares the `HasType`
     * capability, otherwise its tenant's (see `Audience\PrincipalType`). Read
     * from the principal live, not from the token's `pty` claim. Throws as
     * `tenant()` does when the tenant has to be read.
     *
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function type(): ?string
    {
        $principal = $this->principal();

        return $principal === null ? null : PrincipalType::of($principal);
    }

    /**
     * Return the tenant the active principal acts within, if any, resolving the
     * request on first access.
     *
     * Throws `TenantUnavailableException` when the principal names a tenant
     * that opts into activation but cannot be loaded, and a `LogicException`
     * when the principal was loaded without that tenant's key (or polymorphic
     * type). The authentication paths reject such a principal, so this is
     * reached only for one bound through the trusted `login()`, `setUser()`, or
     * `setPrincipal()`, which skip the activity check, or through a custom
     * `getTenant()` that reads the tenant again.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant
    {
        return $this->principal()?->getTenant();
    }

    /**
     * Bind the active principal for the current request and fire the
     * `PrincipalAssigned` custom event.
     *
     * The request is resolved first, so the principal replaces the one the
     * request's credential binds instead of being replaced by it on the next
     * access.
     *
     * A trusted bind, like `login()`: the principal is bound as given, with no
     * check that it belongs to the identity, is active, or acts within an
     * active tenant. A principal taken from request input must be proven to
     * belong to the identity first, as `attempt()` does for the principal
     * pinned on it. The event carries the tenant the principal names, or none
     * when it cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return static
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setPrincipal(Principal $principal): static
    {
        $this->user();

        $this->principal = $principal;

        $this->dispatcher()->dispatch(new PrincipalAssigned($this->boundContext(self::boundTenant($principal), $this->device?->getSignInMethod())));

        return $this;
    }

    /**
     * Bind the active device for the current request and fire the
     * `DeviceAuthenticated` custom event.
     *
     * The request is resolved first, so the device replaces the one the
     * request's credential binds instead of being replaced by it on the next
     * access.
     *
     * A trusted bind, like `login()`: the device is bound as given, with no
     * check that it belongs to the identity, is not revoked, or has a session
     * that has not ended. A device taken from request input must be proven to
     * be one of the identity's live devices first, as `attempt()` does for the
     * device pinned on it. The event carries the tenant the bound principal
     * names, or none when it cannot be loaded, and the method the device's
     * session records.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return static
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setDevice(Device $device): static
    {
        $this->user();

        $this->device = $device;

        $tenant = $this->principal === null ? null : self::boundTenant($this->principal);

        $this->dispatcher()->dispatch(new DeviceAuthenticated($this->boundContext($tenant, $device->getSignInMethod())));

        return $this;
    }

    /**
     * Clear identity, principal, device and credential state without firing
     * events. The caller dispatches any events.
     *
     * @return void
     */
    protected function clearContextualState(): void
    {
        $this->identity     = null;
        $this->principal    = null;
        $this->device       = null;
        $this->credentialId = null;
        $this->scopes       = null;
    }

    /**
     * The tenant a principal bound without an activity check acts within, read
     * on the write connection, or `null` when it names none or the tenant
     * cannot be loaded. A principal loaded without the tenant's key is a
     * misconfiguration, and its `LogicException` propagates.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \LogicException
     */
    private static function boundTenant(Principal $principal): ?Tenant
    {
        try {
            return WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());
        } catch (TenantUnavailableException) {
            return null;
        }
    }

    /**
     * Bind the whole triple, with the credential that authenticated it and the
     * scopes it grants, then dispatch Laravel's `Authenticated`,
     * `PrincipalAssigned` and, with a device, `DeviceAuthenticated`, all
     * describing it, so a listener on any of them sees the complete context.
     * Bound without a credential's scopes, a human identity is not limited
     * (`null`) and a non-human one is limited to none (`[]`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @param  ?string  $credentialId
     * @param  ?list<string>  $scopes
     * @return void
     */
    private function bindContext(
        Identity $identity,
        Principal $principal,
        ?Device $device,
        ?Tenant $tenant,
        ?string $method,
        #[\SensitiveParameter]
        ?string $credentialId = null,
        ?array $scopes = null,
    ): void {
        $this->identity     = $identity;
        $this->principal    = $principal;
        $this->device       = $device;
        $this->credentialId = $credentialId;
        $this->scopes       = $scopes ?? ($identity instanceof MachineIdentity ? [] : null);

        $context = $this->boundContext($tenant, $method);

        $this->dispatcher()->dispatch(new Authenticated($this->name, $identity));
        $this->dispatcher()->dispatch(new PrincipalAssigned($context));

        if ($device === null) {
            return;
        }

        $this->dispatcher()->dispatch(new DeviceAuthenticated($context));
    }

    /**
     * The context of what the guard has bound, for the request it serves.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function boundContext(?Tenant $tenant, ?string $method): EventContext
    {
        return new EventContext(
            $this->name,
            ClientContext::fromRequest($this->request),
            $this->identity,
            $this->principal,
            $tenant,
            $this->device,
            $method,
            credentialId: $this->credentialId,
            scopes: $this->scopes,
        );
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
