<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Guard;

/**
 * Contextual guard contract.
 *
 * Extends Laravel's `Guard` with the package's contextual surface (identity,
 * principal, device, tenant, type, scopes, principal/device setters, contextual
 * `attempt` and `login`). Like `user()`, the accessors and setters resolve the
 * current request on first access, at most once per request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ContextualGuard extends Guard
{
    /**
     * Contextual attempt with optional principal and device pinning.
     *
     * Signature diverges from Laravel's `StatefulGuard::attempt()`: the second
     * and third parameters are contextual pins, not a remember-me flag. This
     * package is stateless-only. Pins are verified against the authenticated
     * identity before they are bound.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return bool
     *
     * @imperative
     */
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Device $device = null): bool;

    /**
     * Bind a fully resolved identity, principal, and optional device.
     *
     * The trusted entry point: the arguments are bound as given, so the caller
     * must already have proven that the principal and device belong to the
     * identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     */
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void;

    /**
     * Return the authenticated identity, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function identity(): ?Identity;

    /**
     * Return the active principal, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principal(): ?Principal;

    /**
     * Return the pinned device, if any, resolving the request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function device(): ?Device;

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
    public function tenant(): ?Tenant;

    /**
     * Return the active principal's type, if any, resolving the request on
     * first access: the principal's own type when it declares the `HasType`
     * capability, otherwise its tenant's (see `Audience\PrincipalType`). Throws
     * as `tenant()` does when the tenant has to be read.
     *
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function type(): ?string;

    /**
     * Return the scopes the request's credential grants, resolving the request
     * on first access: `null` for a human identity's session, which no
     * credential limits, otherwise the granted list (`[]` for none). The scopes
     * are opaque strings and a ceiling, never a permission.
     *
     * @return ?list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function scopes(): ?array;

    /**
     * Bind the active principal for the current request, resolving the request
     * first so it replaces the principal the request's credential binds rather
     * than being replaced by it.
     *
     * A trusted bind, like `login()`: the principal is bound as given, with no
     * check that it belongs to the identity, is active, or acts within an
     * active tenant. A principal taken from request input must be proven to
     * belong to the identity first, as `attempt()` does for the principal
     * pinned on it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return static
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setPrincipal(Principal $principal): static;

    /**
     * Bind the active device for the current request, resolving the request
     * first so it replaces the device the request's credential binds rather
     * than being replaced by it.
     *
     * A trusted bind, like `login()`: the device is bound as given, with no
     * check that it belongs to the identity, is not revoked, or has a session
     * that has not ended. A device taken from request input must be proven to
     * be one of the identity's live devices first, as `attempt()` does for the
     * device pinned on it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return static
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setDevice(Device $device): static;
}
