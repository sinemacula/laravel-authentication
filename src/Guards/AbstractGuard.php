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
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;
use SineMacula\Laravel\Authentication\Guards\Concerns\ExposesCollaborators;
use SineMacula\Laravel\Authentication\Guards\Concerns\RebindsCollaborators;
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
 * to the guard's collaborators via `ExposesCollaborators`, and their rebinding
 * via `RebindsCollaborators`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractGuard implements ContextualGuard
{
    use BindsContextualState, ExposesCollaborators, RebindsCollaborators, SignsInWithCredentials, ValidatesGuardCredentials, VerifiesPinnedContext;

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

        $this->bindContext($user, $principal, null, self::boundTenant($principal), null);

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
     * requirement checks is always the guard's password identifier key (its own
     * `sign_in.password_identifier`, or the package's), however the lookup was
     * written. A value under that key that is not a string, a `Stringable`, an
     * integer or a query closure fails as invalid credentials before any
     * lookup, and the password check is counted against the account it is made
     * for. Once the password is accepted, the identity, the principal and its
     * tenant must be active, the pins must hold, the audience policy must admit
     * the identity as the principal, and the additional-factor policy must not
     * ask for a further factor: `attempt()` cannot hand out a pending sign-in,
     * so a required factor fails it (use the session service's `signIn()`). No
     * device is created.
     *
     * Pins are verified, not trusted, because callers may take them from
     * request input: the principal must resolve through the resolver's hinted
     * path to the same principal of the same class, and the device must be one
     * of the identity's own devices of this guard that is not revoked and whose
     * session has not ended (a device of another guard, or of none, counts as
     * missing). The resolved instances are bound, and a pin that fails either
     * check fails the attempt.
     *
     * A failure fires Laravel's `Failed`, carrying the account the credentials
     * named when there is one, and then `AuthenticationFailed` with the reason.
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
        $identifier = $password->identifier($this->name, $credentials);
        $client     = ClientContext::fromRequest($this->request);
        $outcome    = $this->signInWithCredentials($password, $credentials, $principal, $device, $client);

        if ($outcome instanceof RefusedSignIn) {

            $this->fireFailedEvent($this->lastRetrievedUser, $credentials);

            $this->events->dispatch(new AuthenticationFailed(
                new EventContext($this->name, $client, $outcome->identity, $outcome->principal, $outcome->tenant, $outcome->device, PasswordSignIn::NAME),
                AuthenticationFlow::SIGN_IN,
                $outcome->reason,
                $identifier,
                $outcome->retryAfter,
            ));

            return false;
        }

        // Validated fired when the password was accepted; bind directly and
        // skip login() to avoid double-dispatching.
        $this->bindVerifiedContext($outcome->identity, $outcome->principal, $outcome->device, $outcome->tenant, PasswordSignIn::NAME, true);

        return true;
    }

    /**
     * Bind a fully resolved identity, principal, and optional device, firing
     * `Validated` and `Login` around the bind.
     *
     * Public, trusted entry point for callers that validated the identity
     * out-of-band (refresh, OAuth, SSO): the principal and device are bound as
     * given, without the ownership checks `attempt()` applies to its pins.
     * Paths that already fired `Validated` (as `attempt()` does once the
     * password sign-in method accepts the credentials) call
     * `bindAuthenticationLifecycle()` directly to avoid firing it twice.
     *
     * Previously bound state is cleared first so callers cannot inherit a stale
     * device from a prior login on the same instance. The events carry the
     * tenant the principal names (none when it cannot be loaded) and, with a
     * device, the sign-in method its session records.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     *
     * @throws \LogicException
     */
    #[\Override]
    public function login(Identity $identity, Principal $principal, ?Device $device = null): void
    {
        $this->fireValidatedEvent($identity);

        $this->bindAuthenticationLifecycle($identity, $principal, $device);
    }

    /**
     * Bind a fully resolved identity, principal, and optional device as the
     * request's authentication rather than as a sign-in: only `Authenticated`,
     * `PrincipalAssigned` and, with a device, `DeviceAuthenticated` fire, with
     * no `Validated` and no `Login`.
     *
     * A trusted entry point, like `login()`: the principal and device are bound
     * as given, without ownership, activity or revocation checks, so the caller
     * must have proven them. Previously bound state is cleared first, and the
     * request is settled, so its own credential is not resolved afterwards.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     *
     * @throws \LogicException
     */
    public function authenticateAs(Identity $identity, Principal $principal, ?Device $device = null): void
    {
        $this->bindVerifiedContext($identity, $principal, $device, self::boundTenant($principal), $device?->getSignInMethod(), false);
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
     * Bind an identity to the guard and fire the standard Laravel
     * `Authenticated` event: the hook for a subclass that binds an identity on
     * its own. The package's binds set the whole context before any event
     * instead, so a listener reads all of it.
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
     * contextual triple and dispatch `Authenticated`, `PrincipalAssigned`, and
     * `DeviceAuthenticated` in order. The events carry the tenant the principal
     * names (none when it cannot be loaded) and, with a device, the sign-in
     * method its session records.
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
     *
     * @throws \LogicException
     */
    protected function bindAuthenticationLifecycle(Identity $identity, Principal $principal, ?Device $device = null): void
    {
        $this->bindVerifiedContext($identity, $principal, $device, self::boundTenant($principal), $device?->getSignInMethod(), true);
    }

    /**
     * Bind a context the guard verified itself, with the tenant its activity
     * check loaded and the sign-in method to report: clear prior state and
     * settle the request, dispatch `Login` when it is a sign-in, then bind the
     * triple and dispatch its events.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     * @param  bool  $signIn
     * @return void
     */
    protected function bindVerifiedContext(Identity $identity, Principal $principal, ?Device $device, ?Tenant $tenant, ?string $method, bool $signIn): void
    {
        $this->requestResolved = true;

        $this->clearContextualState();

        if ($signIn) {
            $this->events->dispatch(new Login($this->name, $identity, false));
        }

        $this->bindContext($identity, $principal, $device, $tenant, $method);
    }
}
