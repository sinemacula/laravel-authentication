<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Sessionless JWT bearer-token guard.
 *
 * Reads `Authorization: Bearer <token>` from the active request, decodes via
 * `JwtTokenService`, then rehydrates the live identity, principal, and optional
 * device from the configured provider/resolver/model state before binding them
 * (see `BearerAuthentication`).
 *
 * Exposes `refreshFromRequest()`, which reads the refresh token through the
 * guard's `RefreshTokenTransport`, and `refresh()` for a token the caller read
 * itself; the round trip is delegated to `RefreshTokenExchange`. `sessions()`
 * returns the guard's session service, which starts sessions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtGuard extends AbstractGuard
{
    /** @var ?\SineMacula\Laravel\Authentication\Sessions\SessionService The guard's session service, once built. */
    private ?SessionService $sessions = null;

    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Support\Timebox  $timebox
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange  $exchange
     * @param  \Closure(\SineMacula\Laravel\Authentication\Guards\JwtGuard, \Closure(\Closure(\Illuminate\Support\Timebox): mixed): mixed): \SineMacula\Laravel\Authentication\Sessions\SessionService  $sessionFactory
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transportFactory
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function __construct(

        // Guard name from the auth config.
        string $name,

        // Identity provider backing the guard.
        IdentityProvider $provider,

        // Principal resolver for contextual resolution.
        PrincipalResolver $resolver,

        // Event dispatcher for guard lifecycle events.
        Dispatcher $events,

        // Current HTTP request used to extract credentials.
        Request $request,

        // Timebox enforcing uniform elapsed time on the credential path.
        Timebox $timebox,

        /** JWT token service for access and refresh tokens. */
        protected JwtTokenService $tokens,

        /** Refresh-token exchange for credential rotation. */
        protected RefreshTokenExchange $exchange,

        /** Builds the guard's session service, given the guard and its credential timebox, the first time it is asked for. */
        private readonly \Closure $sessionFactory,

        /** Builds the guard's refresh token transport from the configuration as it is now. */
        private readonly \Closure $transportFactory,
    ) {
        parent::__construct($name, $provider, $resolver, $events, $request, $timebox);
    }

    /**
     * Return the guard's session service, which signs in, creates or continues
     * the device, and issues the first token pair. Built once per guard and
     * handed the guard's credential timebox, so its sign-ins take as long as
     * `attempt()`'s; it reads the guard's request, dispatcher, provider and
     * resolver each time it runs, so it follows their rebinds.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    public function sessions(): SessionService
    {
        return $this->sessions ??= ($this->sessionFactory)($this, $this->context->timebox()->run(...));
    }

    /**
     * Run the callback inside the guard's credential timebox, the one its
     * sign-ins run in, so a check of a secret outside a sign-in (a password
     * reset, a reauthentication) takes as long whatever it found. The callback
     * may end the wait early through the `Timebox` it is given.
     *
     * @template TResult
     *
     * @param  \Closure(\Illuminate\Support\Timebox): TResult  $callback
     * @return TResult
     *
     * @throws \Throwable
     *
     * @internal
     */
    public function timeboxed(\Closure $callback): mixed
    {
        return $this->context->timebox()->run($callback);
    }

    /**
     * Sign the request's session out through the session service: the device
     * the guard is bound to is revoked (`signed_out`) and `DeviceRevoked`
     * reported once committed, Laravel's `Logout` fires when an identity was
     * bound, and the guard stays signed out for the rest of the request. A
     * session without a persisted device is only forgotten.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function logout(): void
    {
        $this->sessions()->signOut();
    }

    /**
     * Exchange a refresh token for a new access token + rotated refresh token.
     *
     * Delegates the round trip to `RefreshTokenExchange`, schedules `Refreshed`
     * and `SignedIn` (with `refresh` set) for once the rotation is committed on
     * the device's connection, and then binds the resolved contextual triple as
     * a sign-in (`Validated`, `Login` and the bind events). Returns `null` on
     * failure, after Laravel's `Failed` and then `AuthenticationFailed` with
     * the reason. Once too many refreshes have failed for the token's device or
     * from the request's IP address, the failure is `rate_limited` and a
     * `ThrottleRequestsException` (429 with `Retry-After`) is thrown after the
     * events instead.
     *
     * The presented token is rotated before the context is bound, so an
     * exception from a listener on `Refreshed` or on the binding events
     * propagates after the rotation and the new pair is lost; a binding
     * listener's cannot withhold `Refreshed`, which was scheduled first. A
     * retry with the presented token inside the grace window gets the current
     * credential; after the window it is treated as a replay and revokes the
     * device.
     *
     * For a token the caller read itself; never pass it one read from the
     * refresh cookie, whose cross-site checks only `refreshFromRequest()`
     * makes.
     *
     * @param  string  $refreshToken
     * @return ?\SineMacula\Laravel\Authentication\Jwt\RefreshResult
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function refresh(#[\SensitiveParameter] string $refreshToken): ?RefreshResult
    {
        $outcome = $this->exchangeRefresh($refreshToken);

        return $outcome instanceof RefreshResult ? $outcome : null;
    }

    /**
     * Refresh with the token the request carries, read through the guard's
     * refresh token transport, so it comes from the one source the guard allows
     * and a cookie passes its cross-site checks.
     *
     * Returns `null`, dispatching nothing, when the request carries no token
     * (nothing was attempted). A token the transport refuses fails with its
     * reason (`refresh_token_conflict`, `cross_site_request`, `token_invalid`)
     * after `Attempting`, `Failed` and `AuthenticationFailed`; a token the
     * exchange refuses fails with the exchange's reason, as `refresh()` does,
     * the 429 for `rate_limited` included. A successful refresh's result says
     * where the token was read from, so a cookie refresh can be answered with a
     * cookie.
     *
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Jwt\RefreshResult|null
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function refreshFromRequest(): FailureReason|RefreshResult|null
    {
        $presented = $this->refreshTransport()->read($this->context->request());

        if ($presented instanceof PresentedRefreshToken) {

            $outcome = $this->exchangeRefresh($presented->token);

            return $outcome instanceof RefreshResult ? new RefreshResult($outcome->accessToken, $outcome->refreshToken, $presented->source) : $outcome;
        }

        if ($presented !== null) {
            $this->fireAttemptingEvent([]);
            $this->refuseRefresh(new AuthenticationFailed(new EventContext($this->context->name(), $this->context->client()), AuthenticationFlow::REFRESH, $presented));
        }

        return $presented;
    }

    /**
     * The guard's refresh token transport, built from the configuration as it
     * is now; a malformed configuration throws an `InvalidArgumentException`
     * naming the guard and the key.
     *
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     */
    public function refreshTransport(): RefreshTokenTransport
    {
        return ($this->transportFactory)();
    }

    /**
     * Rebind the principal resolver onto both the guard and its refresh
     * exchange so bearer and refresh flows continue to share the same policy.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @return static
     */
    #[\Override]
    public function setPrincipalResolver(PrincipalResolver $resolver): static
    {
        parent::setPrincipalResolver($resolver);
        $this->exchange->setPrincipalResolver($resolver);

        return $this;
    }

    /**
     * Rebind the event dispatcher onto both the guard and its refresh exchange,
     * so a dispatcher swapped in after the guard resolved (e.g.
     * `Event::fake()`) receives `DeviceRevoked` as well as the guard's events.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return static
     */
    #[\Override]
    public function setDispatcher(Dispatcher $events): static
    {
        parent::setDispatcher($events);
        $this->exchange->setDispatcher($events);

        return $this;
    }

    /**
     * Resolve the identity from the request's bearer token. `user()` calls this
     * at most once per request, so a rejected token is reported once. A request
     * without a token attempts nothing and dispatches nothing.
     *
     * Fail-closed: a token that claims a specific `pid` or `did` but does not
     * resolve to that exact principal/device is rejected rather than silently
     * downgraded.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    protected function resolveUserFromRequest(): ?Identity
    {
        $token = $this->context->request()->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        return $this->resolveBearerToken($token);
    }

    /**
     * Exchange the token and bind what it names, or refuse it: the result, or
     * the reason the exchange refused it.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Jwt\RefreshResult
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function exchangeRefresh(#[\SensitiveParameter] string $refreshToken): FailureReason|RefreshResult
    {
        $this->fireAttemptingEvent([]);

        $client = $this->context->client();
        $result = $this->exchange->exchange($refreshToken, $client);

        if ($result instanceof AuthenticationFailed) {

            $this->refuseRefresh($result);

            return $result->reason;
        }

        // The rotation is reported before the bind, so a bind listener that
        // throws cannot withhold Refreshed from a rotation already written;
        // the bind then fires the same sequence as attempt().
        $this->reportRefresh($result, $client);

        $this->fireValidatedEvent($result->identity);

        $this->bindVerifiedContext($result->identity, $result->principal, $result->device, $result->tenant, $result->method, true);

        return $result->tokens;
    }

    /**
     * Report a refused refresh, Laravel's `Failed` and then the failure, and
     * answer one the limits refused with a 429 carrying `Retry-After`, since a
     * refresh cannot say so through its return value and a 401 would be wrong.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\AuthenticationFailed  $failure
     * @return void
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private function refuseRefresh(AuthenticationFailed $failure): void
    {
        $this->fireFailedEvent(null, []);

        $this->context->dispatch($failure);

        if ($failure->retryAfter !== null) {
            throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $failure->retryAfter]);
        }
    }

    /**
     * Dispatch `Refreshed` and then `SignedIn` (a refresh, on the device it
     * continued) once the rotation is committed on the device's own connection:
     * at once when it has no open transaction, on its commit otherwise, and
     * never when it rolls back.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh  $result
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    private function reportRefresh(ExchangedRefresh $result, ClientContext $client): void
    {
        $context   = new EventContext($this->context->name(), $client, $result->identity, $result->principal, $result->tenant, $result->device, $result->method);
        $container = Container::getInstance();

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
            ->run($result->device, function () use ($context): void {
                $this->context->dispatch(new Refreshed($context));
                $this->context->dispatch(new SignedIn($context, false, true));
            });
    }

    /**
     * Authenticate a bearer token and bind what it names. A request's token is
     * an authentication, not a sign-in: success binds through
     * `bindVerifiedContext()` without `Validated` or `Login`, so only
     * `Authenticated`, `PrincipalAssigned` and `DeviceAuthenticated` fire, and
     * a rejected token fires only `AuthenticationFailed` with the reason (no
     * `Attempting` or `Failed`).
     *
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveBearerToken(#[\SensitiveParameter] string $token): ?Identity
    {
        $outcome = (new BearerAuthentication($this->context->name(), $this->tokens, $this->context->provider(), $this->context->resolver()))
            ->authenticate($token, $this->context->client());

        if ($outcome instanceof AuthenticationFailed) {

            $this->context->dispatch($outcome);

            return null;
        }

        $admitted = $outcome->admitted;

        $this->bindVerifiedContext(
            $admitted->identity,
            $admitted->principal,
            $admitted->device,
            $admitted->tenant,
            $outcome->method(),
            false,
            $outcome->credentialId,
            $outcome->scopes,
        );

        return $admitted->identity;
    }
}
