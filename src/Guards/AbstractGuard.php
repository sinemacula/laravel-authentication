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
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\SignInFailed;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;
use SineMacula\Laravel\Authentication\Guards\Concerns\ExposesCollaborators;
use SineMacula\Laravel\Authentication\Guards\Concerns\SignsInWithCredentials;
use SineMacula\Laravel\Authentication\Guards\Concerns\ValidatesGuardCredentials;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * Abstract base for the package's stateless contextual guards.
 *
 * Owns the contextual authentication lifecycle, standard and custom event
 * firing, timing-safe credential validation, and Laravel `Guard` contract
 * conformance. Concrete subclasses provide payload extraction and call
 * `attempt()`/`login()` to bind the resolved context.
 *
 * Contextual binding is composed via `BindsContextualState`; the credential
 * event helpers via `ValidatesGuardCredentials`; the sign-in policy checks
 * behind `attempt()` via `SignsInWithCredentials`; ownership checks for
 * principal hints and pinned context via `VerifiesPinnedContext`; read access
 * to the guard's collaborators via `ExposesCollaborators`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractGuard implements ContextualGuard
{
    use BindsContextualState, ExposesCollaborators, SignsInWithCredentials, ValidatesGuardCredentials, VerifiesPinnedContext;

    /** @var ?\Illuminate\Contracts\Auth\Authenticatable Last retrieved user; attached to the `Failed` event. */
    protected ?Authenticatable $lastRetrievedUser = null;

    /** @var bool Whether the current request is settled: resolved, successfully or not, or signed out. */
    protected bool $requestResolved = false;

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

        /** Guard name, as registered under `auth.guards.<name>`. */
        protected string $name,

        /** Identity provider used to look up and validate credentials. */
        protected IdentityProvider $provider,

        /** Resolver that maps an identity to its acting principal. */
        protected PrincipalResolver $resolver,

        /** Event dispatcher for standard and custom auth events. */
        protected Dispatcher $events,

        /** Current HTTP request used to extract credentials. */
        protected Request $request,

        /** Timebox enforcing uniform elapsed time on the credential path. */
        protected Timebox $timebox,
    ) {}

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
     * Resolution runs at most once per request, whether it succeeds or fails,
     * so a bad credential is not re-parsed, re-queried, or re-reported on every
     * call. After `logout()` the guard stays signed out for the rest of the
     * request, as Laravel's session guard does. An explicit `login()`,
     * `attempt()`, or `setUser()` still binds an identity, and a successful
     * `login()` or `attempt()` settles the request as well, so the request's
     * own credential is never resolved in the middle of that sign-in.
     * `setRequest()` starts over for the next request.
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
     * Runs the password sign-in method's credential check inside a single
     * `Timebox::call()`, so elapsed time is uniform whether or not the
     * identifier resolves. Only the credentials are checked: no attempt limit,
     * audience policy or activity check applies, and the password is never
     * rehashed, as with Laravel's own guards.
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

        return $this->timebox->call(function (Timebox $timebox) use ($password, $credentials): bool {

            $identity = $password->verifyCredentials($this->provider, $credentials);

            if ($identity === null) {
                return false;
            }

            $this->fireValidatedEvent($identity);

            $timebox->returnEarly();

            return true;
        }, $this->timeboxMicroseconds());
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
     * The trusted bind behind Laravel's `actingAs()`. The previous identity's
     * principal and device are cleared and the resolver's default principal for
     * the new identity is bound, so the guard never pairs one identity with
     * another's principal or device. Use `login()` to bind a specific principal
     * or a device.
     *
     * Throws an `InvalidArgumentException` when the identity has no default
     * principal. An `UnresolvableIdentityException` from the resolver, for a
     * misconfigured identity model, propagates.
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

        $principal = $this->resolvePrincipal($user);

        if ($principal === null) {
            throw new \InvalidArgumentException(sprintf('Guard %s could not resolve a default principal for identity %s; bind one with login().', $this->name, $user::class));
        }

        $this->clearContextualState();

        $this->setIdentity($user);
        $this->setPrincipal($principal);

        return $this;
    }

    /**
     * Sign in with credentials through the password sign-in method, optionally
     * pinning a specific principal and device on success.
     *
     * The guard's audience policy must allow the `password` method, and the
     * attempt takes one slot from the identifier's and the IP address's sign-in
     * limits before the credentials are checked; a successful sign-in gives its
     * slots back. The credentials keep their full provider semantics, closures
     * included, but the identifier the limits count and the verified-identifier
     * requirement checks is always the configured
     * `authentication.sign_in.password_identifier` key, however the lookup was
     * written. Once the password is accepted, the identity, the principal and
     * its tenant must be active, the pins must hold, the audience policy must
     * admit the identity as the principal, and the additional-factor policy
     * must not ask for a further factor: `attempt()` cannot hand out a pending
     * sign-in, so a required factor fails it (use the session service's
     * `signIn()`). No device is created.
     *
     * Pins are verified, not trusted, because callers may take them from
     * request input: the principal must resolve through the resolver's hinted
     * path to the same principal of the same class, and the device must be one
     * of the identity's own devices that is not revoked and whose session has
     * not ended. The resolved instances are bound, and a pin that fails either
     * check fails the attempt.
     *
     * A failure fires Laravel's `Failed`, carrying the account the credentials
     * named when there is one, and then `SignInFailed` with the reason.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    #[\Override]
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Device $device = null): bool
    {
        $this->lastRetrievedUser = null;

        $this->fireAttemptingEvent($credentials);

        $password   = self::signInCollaborator(PasswordSignIn::class);
        $identifier = $password->identifier($credentials);
        $client     = ClientContext::fromRequest($this->request);
        $outcome    = $this->signInWithCredentials($password, $credentials, $principal, $device, $client);

        if ($outcome instanceof RefusedSignIn) {

            $this->fireFailedEvent($this->lastRetrievedUser, $credentials);

            $this->events->dispatch(new SignInFailed(
                $this->name,
                $outcome->identity,
                $outcome->principal,
                $outcome->tenant,
                $outcome->device,
                PasswordSignIn::NAME,
                $client,
                $outcome->reason,
                $identifier,
                $outcome->retryAfter,
            ));

            return false;
        }

        // Validated fired when the password was accepted; bind directly and
        // skip login() to avoid double-dispatching.
        $this->bindAuthenticationLifecycle($outcome->identity, $outcome->principal, $outcome->device);

        return true;
    }

    /**
     * Bind a fully resolved identity, principal, and optional device, firing
     * `Validated` and `Login` around the bind.
     *
     * Public, trusted entry point for callers that validated the identity
     * out-of-band (refresh, OAuth, SSO): the principal and device are bound as
     * given, without the ownership checks `attempt()` applies to its pins.
     * Paths that already went through `hasValidCredentials()` should call
     * `bindAuthenticationLifecycle()` directly to avoid double-firing
     * `Validated`.
     *
     * Previously bound state is cleared first so callers cannot inherit a stale
     * device from a prior login on the same instance.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     */
    #[\Override]
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void
    {
        $this->fireValidatedEvent($identity);

        $this->bindAuthenticationLifecycle($identity, $principal, $device);
    }

    /**
     * Sign the request out: fire the standard Laravel `Logout` event when the
     * request is authenticated, resolving it first as Laravel's session guard
     * does, then clear all bound state. The guard stays signed out for the rest
     * of the request instead of resolving the request's credential again.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function logout(): void
    {
        $identity = $this->user();

        if ($identity !== null) {
            $this->events->dispatch(new Logout($this->name, $identity));
        }

        $this->clearContextualState();

        $this->requestResolved = true;
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
     * Rebind the current HTTP request onto the guard and forget everything
     * resolved for the previous one. Called by the service provider on each
     * container-resolve cycle.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return static
     */
    public function setRequest(Request $request): static
    {
        $this->request           = $request;
        $this->lastRetrievedUser = null;
        $this->requestResolved   = false;
        $this->clearContextualState();

        return $this;
    }

    /**
     * Rebind the event dispatcher onto the guard, so test suites that swap it
     * after the guard is resolved (e.g. `Event::fake()`) get a fresh reference.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return static
     */
    public function setDispatcher(Dispatcher $events): static
    {
        $this->events = $events;

        return $this;
    }

    /**
     * Rebind the principal resolver, so consumers that swap it after guard
     * construction (test fakes, runtime tenancy switches) propagate the new
     * resolver into the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @return static
     */
    public function setPrincipalResolver(PrincipalResolver $resolver): static
    {
        $this->resolver = $resolver;

        return $this;
    }

    /**
     * Bind an identity to the guard and fire the standard Laravel
     * `Authenticated` event. Shared entry point for `setUser()` and the
     * contextual `login()` path.
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
     * Resolve a principal for the identity through the bound resolver.
     *
     * An `UnresolvableIdentityException` (an identity model that is neither a
     * `Principal` nor `HasPrincipals`) is a misconfiguration, not a failed
     * authentication, so it propagates as a server error rather than being
     * reported as a `Failed` attempt.
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
            ? $this->resolver->resolve($identity)
            : $this->resolver->resolve($identity, $hint);
    }

    /**
     * Resolve the identity carried by the current request and bind its context,
     * returning `null` when the request carries no valid credential.
     *
     * Called by `user()` at most once per request. The base guard reads no
     * request credential; request-authenticating guards override this.
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
     * Internal bind: clear prior state, dispatch `Login`, then set the
     * contextual triple (which dispatches `Authenticated`, `PrincipalAssigned`,
     * and `DeviceAuthenticated` in order).
     *
     * Login-before-Authenticated mirrors Laravel's `SessionGuard::login()`.
     *
     * An explicit bind settles the request: a `Login` listener that reads the
     * guard before the identity is set gets no identity rather than resolving
     * the request's own credential, whose device would otherwise stay bound to
     * the identity signing in.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     */
    protected function bindAuthenticationLifecycle(Identity $identity, Principal $principal, ?Device $device = null): void
    {
        $this->requestResolved = true;

        $this->clearContextualState();

        $this->events->dispatch(new Login($this->name, $identity, false));

        $this->setIdentity($identity);
        $this->setPrincipal($principal);

        if ($device === null) {
            return;
        }

        $this->setDevice($device);
    }
}
