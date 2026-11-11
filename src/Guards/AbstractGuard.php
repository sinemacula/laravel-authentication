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
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\HasGuardContext;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;
use SineMacula\Laravel\Authentication\Guards\Concerns\ExposesCollaborators;
use SineMacula\Laravel\Authentication\Guards\Concerns\HoldsAuthenticationContext;
use SineMacula\Laravel\Authentication\Guards\Concerns\RebindsCollaborators;
use SineMacula\Laravel\Authentication\Guards\Concerns\SignsInWithCredentials;
use SineMacula\Laravel\Authentication\Guards\Concerns\ValidatesGuardCredentials;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Runtime\CredentialTimebox;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * Abstract base for the package's stateless contextual guards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractGuard implements ContextualGuard, GuardBinding, HasGuardContext
{
    use BindsContextualState, ExposesCollaborators, HoldsAuthenticationContext, RebindsCollaborators, SignsInWithCredentials, ValidatesGuardCredentials, VerifiesPinnedContext;

    /** @var ?\Illuminate\Contracts\Auth\Authenticatable Last retrieved user; attached to the `Failed` event. */
    protected ?Authenticatable $lastRetrievedUser = null;

    /** @var bool Whether the current request is settled: resolved, successfully or not, or signed out. */
    protected bool $requestResolved = false;

    /** @var \SineMacula\Laravel\Authentication\Runtime\GuardContext The collaborators the guard's flows run with, which its setters rebind. */
    protected readonly GuardContext $context;

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

        // Guard name, as registered under `auth.guards.<name>`.
        string $name,

        // Identity provider used to look up and validate credentials.
        IdentityProvider $provider,

        // Resolver that maps an identity to its acting principal.
        PrincipalResolver $resolver,

        // Event dispatcher for standard and custom auth events.
        Dispatcher $events,

        // Current HTTP request used to extract credentials.
        Request $request,

        // Timebox enforcing uniform elapsed time on the credential path.
        Timebox $timebox,
    ) {
        $this->context = new GuardContext($name, $provider, $resolver, $events, $request, new CredentialTimebox($timebox));
    }

    /**
     * Determine if the current request has no authenticated identity, resolving
     * the request on first access.
     *
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     *
     * @imperative
     */
    #[\Override]
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * Determine if the current request has an authenticated identity, resolving
     * the request on first access.
     *
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     *
     * @imperative
     */
    #[\Override]
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Return the authenticated identity, resolving it from the current request
     * on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function user(): ?Identity
    {
        if ($this->identity !== null || $this->requestResolved) {
            return $this->identity;
        }

        // Recorded before resolving, so a failure is not retried and a listener
        // that calls user() during resolution does not re-enter it.
        $this->requestResolved = true;

        return $this->resolveUserFromRequest();
    }

    /**
     * Return the auth identifier of the authenticated identity, if any,
     * resolving the request on first access.
     *
     * @return int|string|null
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function id(): int|string|null
    {
        $identifier = $this->user()?->getAuthIdentifier();

        if ($identifier === null || is_int($identifier) || is_string($identifier)) {
            return $identifier;
        }

        return null;
    }

    /**
     * Validate credentials without mutating guard state, firing `Validated`
     * when they are accepted.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     *
     * @throws \Throwable
     */
    #[\Override]
    public function validate(#[\SensitiveParameter] array $credentials = []): bool
    {
        $password = self::signInCollaborator(PasswordSignIn::class);

        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $held = new \SensitiveParameterValue($credentials);

        return $this->context->timebox()->run(function (Timebox $timebox) use ($password, $held): bool {

            $identity = $password->verifyCredentials($this->context->provider(), $held->getValue());

            if ($identity === null) {
                return false;
            }

            $this->fireValidatedEvent($identity);

            $timebox->returnEarly();

            return true;
        });
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
     * Bind an authenticated identity to the guard with its default principal.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return $this
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function setUser(Authenticatable $user): self
    {
        $name = $this->context->name();

        if (!$user instanceof Identity) {
            throw new \InvalidArgumentException(sprintf('Guard %s expected an Identity instance, got %s.', $name, $user::class));
        }

        $principal = $this->resolvePrincipal($user);

        if ($principal === null) {
            throw new \InvalidArgumentException(sprintf('Guard %s could not resolve a default principal for identity %s; bind one with login().', $name, $user::class));
        }

        $this->clearContextualState();

        $this->bindContext($user, $principal, null, self::boundTenant($principal), null);

        return $this;
    }

    /**
     * Sign in with credentials through the password sign-in method, optionally
     * pinning a specific principal and session on success.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    #[\Override]
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Session $session = null): bool
    {
        $this->lastRetrievedUser = null;

        $this->fireAttemptingEvent($credentials);

        $password   = self::signInCollaborator(PasswordSignIn::class);
        $identifier = $password->identifier($this->context->name(), $credentials);
        $client     = $this->context->client();
        $outcome    = $this->signInWithCredentials($password, $credentials, $principal, $session, $client);

        if ($outcome instanceof Refused) {

            $this->fireFailedEvent($this->lastRetrievedUser, $credentials);

            $this->context->dispatch(new AuthenticationFailed(
                new EventContext($this->context->name(), $client, $outcome->identity, $outcome->principal, $outcome->tenant, $outcome->session, PasswordSignIn::NAME),
                AuthenticationFlow::SIGN_IN,
                $outcome->reason,
                $identifier,
                $outcome->retryAfter,
            ));

            return false;
        }

        // Validated fired when the password was accepted; bind directly and
        // skip login() to avoid double-dispatching.
        $this->bindVerifiedContext($outcome->identity, $outcome->principal, $outcome->session, $outcome->tenant, PasswordSignIn::NAME, true);

        return true;
    }

    /**
     * Bind a fully resolved identity, principal, and optional session, firing
     * `Validated` and `Login` around the bind.
     *
     * A trusted bind: nothing given is checked against the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \LogicException
     */
    #[\Override]
    public function login(Identity $identity, Principal $principal, ?Session $session = null, ?ClientContext $client = null): void
    {
        $this->fireValidatedEvent($identity);

        $this->bindAuthenticationLifecycle($identity, $principal, $session, $client);
    }

    /**
     * Bind a fully resolved identity, principal and optional session as the
     * request's authentication, firing neither `Validated` nor `Login`.
     *
     * A trusted bind: nothing given is checked against the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?list<string>  $scopes
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function authenticateAs(
        Identity $identity,
        Principal $principal,
        ?Session $session = null,
        ?array $scopes = null,
        ?Tenant $tenant = null,
        ?ClientContext $client = null,
    ): void {
        self::assertScopable($identity, $scopes);

        $this->bindVerifiedContext(
            $identity,
            $principal,
            $session,
            $tenant ?? self::trustedTenant($principal, $session),
            $session?->getSignInMethod(),
            false,
            null,
            $scopes,
            client: $client,
        );
    }

    /**
     * Sign the request out, firing Laravel's `Logout` when it is authenticated,
     * and keep it signed out for the rest of the request.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function logout(): void
    {
        $identity = $this->user();

        if ($identity !== null) {
            $this->context->dispatch(new Logout($this->context->name(), $identity));
        }

        $this->clearContextualState();

        $this->requestResolved = true;
    }

    /**
     * Forget the bound identity, principal and session without an event,
     * keeping the guard signed out for the rest of the request.
     *
     * @return static
     */
    #[\Override]
    public function forgetUser(): static
    {
        $this->clearContextualState();

        $this->requestResolved = true;

        return $this;
    }

    /**
     * Return the registered name of this guard.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->context->name();
    }

    /**
     * Return the context the guard's flows run with.
     *
     * @return \SineMacula\Laravel\Authentication\Runtime\GuardContext
     */
    #[\Override]
    public function context(): GuardContext
    {
        return $this->context;
    }

    /**
     * Bind an identity to the guard and fire Laravel's `Authenticated` event.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return void
     */
    protected function setIdentity(Identity $identity): void
    {
        $this->identity              = $identity;
        $this->authenticationContext = null;
        $this->credentialKind        = null;

        $this->context->dispatch(new Authenticated($this->context->name(), $identity));
    }

    /**
     * Resolve a principal for the identity through the bound resolver.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    protected function resolvePrincipal(Identity $identity, mixed $hint = null): ?Principal
    {
        return $hint === null
            ? $this->context->resolver()->resolve($identity)
            : $this->context->resolver()->resolve($identity, $hint);
    }

    /**
     * Resolve the identity carried by the current request and bind its context,
     * returning `null` when the request carries no valid credential.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    protected function resolveUserFromRequest(): ?Identity
    {
        return null;
    }

    /**
     * Bind as a sign-in, in the tenant the session records (or the principal's
     * own without a session), with the sign-in method the session records.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    protected function bindAuthenticationLifecycle(Identity $identity, Principal $principal, ?Session $session = null, ?ClientContext $client = null): void
    {
        $this->bindVerifiedContext($identity, $principal, $session, self::trustedTenant($principal, $session), $session?->getSignInMethod(), true, client: $client);
    }

    /**
     * Bind a context the guard verified itself, dispatching `Login` for a
     * sign-in before the bind's own events.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null  $tenant
     * @param  ?string  $method
     * @param  bool  $signIn
     * @param  ?string  $credentialId
     * @param  ?list<string>  $scopes
     * @param  ?\SineMacula\Laravel\Authentication\Context\Enums\CredentialKind  $kind
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    protected function bindVerifiedContext(
        Identity $identity,
        Principal $principal,
        ?Session $session,
        Tenant|TenantUnavailableException|null $tenant,
        ?string $method,
        bool $signIn,
        #[\SensitiveParameter]
        ?string $credentialId = null,
        ?array $scopes = null,
        ?CredentialKind $kind = null,
        ?ClientContext $client = null,
    ): void {
        $this->requestResolved = true;

        $this->clearContextualState();

        $this->credentialKind = $kind;

        if ($signIn) {
            $this->context->dispatch(new Login($this->context->name(), $identity, false));
        }

        $this->credentialId = $credentialId;
        $this->scopes       = $scopes;

        $this->bindContext($identity, $principal, $session, $tenant, $method, $client);
    }
}
