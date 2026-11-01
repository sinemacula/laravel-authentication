<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Validated;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;

/**
 * Holds the identity -> principal -> session triple bound to a guard, with the
 * active tenant, the credential that authenticated it and the scopes that
 * credential grants, and exposes accessors plus setters that fire the
 * contextual events. Each event carries the whole bound context, set before it
 * is dispatched, with the request's client.
 *
 * Every accessor goes through the host guard's `user()`, so the first access on
 * a request resolves it, as Laravel's own guards do, even on a route without
 * authentication middleware.
 *
 * Expects the using class to hold the guard's `GuardContext` in
 * `$this->context`, whose name, dispatcher and request it reads, and to declare
 * `bindVerifiedContext()`, which `loginVerified()` binds through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
 *
 * @property \SineMacula\Laravel\Authentication\Runtime\GuardContext $context
 */
trait BindsContextualState
{
    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Identity Identity bound to the guard, if any. */
    protected ?Identity $identity = null;

    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Principal Principal bound to the guard, if any. */
    protected ?Principal $principal = null;

    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Session Session bound to the guard, if any. */
    protected ?Session $session = null;

    /** @var ?string Identifier of the credential (an API key) that authenticated the bound identity, if any. */
    protected ?string $credentialId = null;

    /** @var ?list<string> Scopes the bound context is limited to; `null` when no credential limits it. */
    protected ?array $scopes = null;

    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Tenant The active tenant bound to the guard, if any. */
    protected ?Tenant $activeTenant = null;

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
     * Return the pinned session, if any, resolving the request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function session(): ?Session
    {
        $this->user();

        return $this->session;
    }

    /**
     * Return the scopes the request's credential grants, resolving the request
     * on first access: `null` for a human identity's session, which no
     * credential limits, and the granted list (`[]` for none) for an API key or
     * a client-credentials token. A non-human identity bound without a
     * credential (through the trusted `login()`, `setUser()` or
     * `authenticateAs()`) gets `[]`: a machine is always limited. The package
     * carries scopes and never interprets them; they are a ceiling the
     * application's authorisation intersects with the principal's permissions.
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
     * Return the active tenant, the one the request acts in, if any, resolving
     * the request on first access: the one its admission found (a session's
     * recorded tenant, or the principal's own for a token without a session),
     * or, for a trusted bind (`login()`, `setUser()`, `authenticateAs()`,
     * `setPrincipal()`, `setSession()`), the tenant the bound session records
     * (none when it no longer resolves or is inactive) or, with no session, the
     * principal's own (none when it cannot be loaded). It is read when the
     * context is bound, on the write connection, and held until it is bound
     * again or forgotten.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant
    {
        $this->user();

        return $this->activeTenant;
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
     * pinned on it. The active tenant becomes the one the bound session records
     * for the principal, or the principal's own when no session is bound, and
     * the event carries it (none when it cannot be loaded).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setPrincipal(Principal $principal): static
    {
        $this->user();

        $this->principal = $principal;

        $this->activeTenant = self::trustedTenant($principal, $this->session);

        $this->context->dispatch(new PrincipalAssigned($this->boundContext($this->activeTenant, $this->session?->getSignInMethod())));

        return $this;
    }

    /**
     * Bind the active session for the current request and fire the
     * `SessionAuthenticated` custom event.
     *
     * The request is resolved first, so the session replaces the one the
     * request's credential binds instead of being replaced by it on the next
     * access.
     *
     * A trusted bind, like `login()`: the session is bound as given, with no
     * check that it belongs to the identity, is not revoked, or has not ended.
     * A session taken from request input must be proven to be one of the
     * identity's live sessions first, as `attempt()` does for the session
     * pinned on it. The active tenant becomes the one the session records for
     * the bound principal (none when it no longer resolves or is inactive), and
     * the event carries it with the method the session records.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setSession(Session $session): static
    {
        $this->user();

        $this->session = $session;

        if ($this->principal !== null) {
            $this->activeTenant = self::trustedTenant($this->principal, $session);
        }

        $this->context->dispatch(new SessionAuthenticated($this->boundContext($this->activeTenant, $session->getSignInMethod())));

        return $this;
    }

    /**
     * Bind a context the flow verified itself as a sign-in: `Validated`, then
     * `Login` and the bind events, with the tenant the flow's activity check
     * loaded and the sign-in method it reports, as a refresh binds the session
     * it rotated. The context is bound as given, without the ownership checks
     * `attempt()` applies to its pins, so the caller must have proven it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @return void
     */
    public function loginVerified(Identity $identity, Principal $principal, ?Session $session, ?Tenant $tenant, ?string $method): void
    {
        $this->context->dispatch(new Validated($this->context->name(), $identity));

        $this->bindVerifiedContext($identity, $principal, $session, $tenant, $method, true);
    }

    /**
     * Clear identity, principal, session and credential state without firing
     * events. The caller dispatches any events.
     *
     * @return void
     */
    protected function clearContextualState(): void
    {
        $this->identity     = null;
        $this->principal    = null;
        $this->session      = null;
        $this->credentialId = null;
        $this->scopes       = null;
        $this->activeTenant = null;
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
     * The active tenant of a trusted bind: with a session, the tenant the
     * session records for the principal (`null` when it no longer resolves or
     * is inactive; no access contract is asked); without one, the principal's
     * own as `boundTenant()` reads it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function trustedTenant(Principal $principal, ?Session $session): ?Tenant
    {
        if ($session === null) {
            return self::boundTenant($principal);
        }

        $tenant = TenantAdmission::recorded($principal, WriteConnection::during($session, static fn (): ?string => $session->getTenantId()), false);

        return $tenant instanceof FailureReason ? null : $tenant;
    }

    /**
     * Refuse scopes for an identity that is not a machine: scopes limit a
     * credential, and no credential limits a human identity's session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?list<string>  $scopes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertScopable(Identity $identity, ?array $scopes): void
    {
        if ($scopes === null || $identity instanceof MachineIdentity) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('Scopes limit the credential of a machine identity; %s is not one, so no credential limits it.', $identity::class));
    }

    /**
     * Bind the whole triple, with the credential that authenticated it and the
     * scopes it grants, then dispatch Laravel's `Authenticated`,
     * `PrincipalAssigned` and, with a session, `SessionAuthenticated`, all
     * describing it, so a listener on any of them sees the complete context.
     * Bound without a credential's scopes, a human identity is not limited
     * (`null`) and a non-human one is limited to none (`[]`). The tenant is
     * bound as the active tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @param  ?string  $credentialId
     * @param  ?list<string>  $scopes
     * @return void
     */
    private function bindContext(
        Identity $identity,
        Principal $principal,
        ?Session $session,
        ?Tenant $tenant,
        ?string $method,
        #[\SensitiveParameter]
        ?string $credentialId = null,
        ?array $scopes = null,
    ): void {
        $this->identity     = $identity;
        $this->principal    = $principal;
        $this->session      = $session;
        $this->credentialId = $credentialId;
        $this->scopes       = $scopes ?? ($identity instanceof MachineIdentity ? [] : null);
        $this->activeTenant = $tenant;

        $context = $this->boundContext($tenant, $method);

        $this->context->dispatch(new Authenticated($this->context->name(), $identity));
        $this->context->dispatch(new PrincipalAssigned($context));

        if ($session === null) {
            return;
        }

        $this->context->dispatch(new SessionAuthenticated($context));
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
            $this->context->name(),
            $this->context->client(),
            $this->identity,
            $this->principal,
            $tenant,
            $this->session,
            $method,
            credentialId: $this->credentialId,
            scopes: $this->scopes,
        );
    }
}
