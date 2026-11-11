<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Validated;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Holds the identity, principal and session bound to a guard, with its active
 * tenant and credential, and fires the contextual events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\GuardBinding
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

    /** @var ?\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException Why the active tenant a trusted bind found cannot be loaded, when it cannot. */
    protected ?TenantUnavailableException $unavailableTenant = null;

    /** @var ?\SineMacula\Laravel\Authentication\Context\Enums\CredentialKind The kind of credential the request presented, when the guard authenticated one. */
    protected ?CredentialKind $credentialKind = null;

    /** @var int The last version handed out to any guard's bound state. */
    private static int $boundStateVersions = 0;

    /** @var ?int The bound state's version, once asked for since it changed. */
    private ?int $boundStateVersion = null;

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
     * Return the scopes the request's credential grants, or `null` when no
     * credential limits the context, resolving the request on first access.
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
     * Return the active tenant the request acts in, if any, resolving the
     * request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant
    {
        $this->user();

        if ($this->unavailableTenant !== null) {
            throw $this->unavailableTenant;
        }

        return $this->activeTenant;
    }

    /**
     * The bound state's version, unique across guards and replaced on change.
     *
     * @return int
     *
     * @internal
     */
    public function boundStateVersion(): int
    {
        return $this->boundStateVersion ??= ++self::$boundStateVersions;
    }

    /**
     * Bind the active principal for the current request and fire
     * `PrincipalAssigned`.
     *
     * Trusted: a principal taken from request input must be proven first.
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

        $this->forgetDerivedState();

        $this->bindTenant(self::trustedTenant($principal, $this->session));

        $this->context->dispatch(new PrincipalAssigned($this->boundContext($this->activeTenant, $this->session?->getSignInMethod())));

        return $this;
    }

    /**
     * Bind the active session for the current request and fire
     * `SessionAuthenticated`.
     *
     * Trusted: a session taken from request input must be proven first.
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

        $this->forgetDerivedState();

        if ($this->principal !== null) {
            $this->bindTenant(self::trustedTenant($this->principal, $session));
        }

        $this->context->dispatch(new SessionAuthenticated($this->boundContext($this->activeTenant, $session->getSignInMethod())));

        return $this;
    }

    /**
     * Bind a context the flow verified itself as a sign-in, firing `Validated`,
     * `Login` and the bind events.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    public function loginVerified(Identity $identity, Principal $principal, ?Session $session, ?Tenant $tenant, ?string $method, ?ClientContext $client = null): void
    {
        $this->context->dispatch(new Validated($this->context->name(), $identity));

        $this->bindVerifiedContext($identity, $principal, $session, $tenant, $method, true, client: $client);
    }

    /**
     * Forget the bound identity, principal and session when the bound session
     * is the one given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     */
    #[\Override]
    public function forgetSession(Session $session): void
    {
        if (!$this->isBoundToSession($session)) {
            return;
        }

        $this->forgetUser();
    }

    /**
     * Forget the bound identity, principal and session when the bound identity
     * is the one given and the bound session is not the one kept.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $kept
     * @return void
     */
    #[\Override]
    public function forgetIdentity(Identity $identity, ?Session $kept = null): void
    {
        $bound = $this->identity;

        if ($bound === null || $bound::class !== $identity::class || !IdentifierCoercion::matches($bound->getAuthIdentifier(), $identity->getAuthIdentifier())) {
            return;
        }

        if ($kept !== null && $this->isBoundToSession($kept)) {
            return;
        }

        $this->forgetUser();
    }

    /**
     * Clear identity, principal, session and credential state, and what was
     * read from them, without firing events.
     *
     * @return void
     */
    protected function clearContextualState(): void
    {
        $this->identity          = null;
        $this->principal         = null;
        $this->session           = null;
        $this->credentialId      = null;
        $this->credentialKind    = null;
        $this->scopes            = null;
        $this->activeTenant      = null;
        $this->unavailableTenant = null;

        $this->forgetDerivedState();
    }

    /**
     * Forget the authentication context and version of the bound state.
     *
     * @return void
     */
    private function forgetDerivedState(): void
    {
        $this->authenticationContext = null;
        $this->boundStateVersion     = null;
    }

    /**
     * The tenant a principal bound without an activity check acts within,
     * `null` when it names none, or why it cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null
     *
     * @throws \LogicException
     */
    private static function boundTenant(Principal $principal): Tenant|TenantUnavailableException|null
    {
        try {
            return WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());
        } catch (TenantUnavailableException $exception) {
            return $exception;
        }
    }

    /**
     * The active tenant of a trusted bind: the one the session records for the
     * principal, or the principal's own without a session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function trustedTenant(Principal $principal, ?Session $session): Tenant|TenantUnavailableException|null
    {
        return $session === null
            ? self::boundTenant($principal)
            : self::recordedTenant($principal, WriteConnection::during($session, static fn (): ?string => $session->getTenantId()));
    }

    /**
     * The tenant a session records for the principal, unchecked, `null` when it
     * records none, or why it cannot be loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function recordedTenant(Principal $principal, ?string $tenantId): Tenant|TenantUnavailableException|null
    {
        if ($tenantId === null) {
            return null;
        }

        $own    = self::boundTenant($principal);
        $tenant = TenantAdmission::named($principal, $own instanceof Tenant ? $own : null, $tenantId);

        return $tenant ?? ($own instanceof TenantUnavailableException ? $own : self::unresolvable($tenantId));
    }

    /**
     * The reason a tenant a session records cannot be bound: it no longer
     * resolves.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    private static function unresolvable(string $tenantId): TenantUnavailableException
    {
        return new TenantUnavailableException(sprintf('The tenant %s the bound session records cannot be resolved.', $tenantId));
    }

    /**
     * Bind the active tenant a bind found, or the reason it cannot be loaded,
     * which `tenant()` throws while the context stays bound.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null  $tenant
     * @return void
     */
    private function bindTenant(Tenant|TenantUnavailableException|null $tenant): void
    {
        $this->activeTenant      = $tenant instanceof Tenant ? $tenant : null;
        $this->unavailableTenant = $tenant instanceof TenantUnavailableException ? $tenant : null;
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
     * Bind the whole triple with its credential and scopes, then dispatch its
     * events.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null  $tenant
     * @param  ?string  $method
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    private function bindContext(
        Identity $identity,
        Principal $principal,
        ?Session $session,
        Tenant|TenantUnavailableException|null $tenant,
        ?string $method,
        ?ClientContext $client = null,
    ): void {
        $this->identity  = $identity;
        $this->principal = $principal;
        $this->session   = $session;
        $this->scopes ??= $identity instanceof MachineIdentity ? [] : null;

        $this->bindTenant($tenant);

        // A `Login` listener may have read the cleared state.
        $this->forgetDerivedState();

        $context = $this->boundContext($this->activeTenant, $method, $client);

        $this->context->dispatch(new Authenticated($this->context->name(), $identity));
        $this->context->dispatch(new PrincipalAssigned($context));

        if ($session === null) {
            return;
        }

        $this->context->dispatch(new SessionAuthenticated($context));
    }

    /**
     * The context of what the guard has bound, for the client given or, without
     * one, the request the guard serves.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function boundContext(?Tenant $tenant, ?string $method, ?ClientContext $client = null): EventContext
    {
        return new EventContext(
            $this->context->name(),
            $client ?? $this->context->client(),
            $this->identity,
            $this->principal,
            $tenant,
            $this->session,
            $method,
            credentialId: $this->credentialId,
            scopes: $this->scopes,
        );
    }

    /**
     * Whether the guard is bound to the session given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return bool
     */
    private function isBoundToSession(Session $session): bool
    {
        return $this->session !== null && IdentifierCoercion::matches($this->session->getSessionIdentifier(), $session->getSessionIdentifier());
    }
}
