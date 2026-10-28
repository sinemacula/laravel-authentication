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
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
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
 * device from the configured provider/resolver/model state before binding them.
 *
 * Exposes `refresh()` for refresh-credential exchange; the round trip is
 * delegated to `RefreshTokenExchange`. `sessions()` returns the guard's session
 * service, which starts sessions.
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
        return $this->sessions ??= ($this->sessionFactory)($this, fn (\Closure $callback): mixed => $this->timebox->call($callback, $this->timeboxMicroseconds()));
    }

    /**
     * Exchange a refresh token for a new access token + rotated refresh token.
     *
     * Delegates the round trip to `RefreshTokenExchange`, binds the resolved
     * contextual triple, and dispatches `Refreshed` once the rotation is
     * committed on the device's connection. Returns `null` on failure, after
     * Laravel's `Failed` and then `AuthenticationFailed` with the reason. Once
     * too many refreshes have failed for the token's device or from the
     * request's IP address, the failure is `rate_limited` and a
     * `ThrottleRequestsException` (429 with `Retry-After`) is thrown after the
     * events instead.
     *
     * The presented token is rotated before the context is bound, so an
     * exception from a listener on the binding events or on `Refreshed`
     * propagates after the rotation and the new pair is lost. A retry with the
     * presented token inside the grace window gets the current credential;
     * after the window it is treated as a replay and revokes the device.
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
        $this->fireAttemptingEvent([]);

        $client = ClientContext::fromRequest($this->request);
        $result = $this->exchange->exchange($refreshToken, $client);

        if ($result instanceof AuthenticationFailed) {

            $this->fireFailedEvent(null, []);

            $this->events->dispatch($result);

            self::refuseIfRateLimited($result);

            return null;
        }

        // Validated then the full bind, so a refresh fires the same event
        // sequence as attempt(); Refreshed follows once the rotation commits so
        // consumers can tell a rotation from a sign-in.
        $this->fireValidatedEvent($result->identity);

        $this->bindVerifiedContext($result->identity, $result->principal, $result->device, $result->tenant, $result->method, true);

        $this->reportRefresh($result, $client);

        return $result->tokens;
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
     * at most once per request.
     *
     * Fail-closed: a token that claims a specific `pid` or `did` but does not
     * resolve to that exact principal/device is rejected rather than silently
     * downgraded.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    protected function resolveUserFromRequest(): ?Identity
    {
        $token = $this->request->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        return $this->resolveBearerToken($token);
    }

    /**
     * Answer a refresh the limits refused with a 429 carrying `Retry-After`,
     * since `refresh()` cannot say so through its return value and a 401 would
     * be wrong.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\AuthenticationFailed  $failure
     * @return void
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private static function refuseIfRateLimited(AuthenticationFailed $failure): void
    {
        if ($failure->retryAfter !== null) {
            throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $failure->retryAfter]);
        }
    }

    /**
     * Dispatch `Refreshed` once the rotation is committed on the device's own
     * connection: at once when it has no open transaction, on its commit
     * otherwise, and never when it rolls back.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh  $result
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    private function reportRefresh(ExchangedRefresh $result, ClientContext $client): void
    {
        $context   = new EventContext($this->name, $client, $result->identity, $result->principal, $result->tenant, $result->device, $result->method);
        $container = Container::getInstance();

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
            ->run($result->device, function () use ($context): void {
                $this->events->dispatch(new Refreshed($context));
            });
    }

    /**
     * Decode a bearer token, fire success events, and bind
     * identity/principal/device. Returns the bound identity, or `null` after
     * firing `Failed`.
     *
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveBearerToken(#[\SensitiveParameter] string $token): ?Identity
    {
        $this->fireAttemptingEvent([]);

        // Reset so a prior request's user cannot leak onto this failure path.
        $this->lastRetrievedUser = null;

        $context = $this->resolveContextFromToken($token);

        if ($context === null) {

            $this->fireFailedEvent($this->lastRetrievedUser, []);

            return null;
        }

        $this->fireValidatedEvent($context['identity']);

        $this->bindVerifiedContext($context['identity'], $context['principal'], $context['device'], $context['tenant'], $context['device']?->getSignInMethod(), true);

        return $context['identity'];
    }

    /**
     * Resolve identity, principal, the principal's tenant, and device from a
     * parsed bearer token. The caller fires `Failed` and binds state.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $token
     * @return array{identity: \SineMacula\Laravel\Authentication\Contracts\Identity, principal: \SineMacula\Laravel\Authentication\Contracts\Principal, tenant: ?\SineMacula\Laravel\Authentication\Contracts\Tenant, device: ?\SineMacula\Laravel\Authentication\Contracts\Device}|null
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveContextFromToken(#[\SensitiveParameter] string $token): ?array
    {
        $claims = $this->tokens->parse($token, TokenType::ACCESS);
        $user   = $this->loadIdentityFromClaims($claims);
        $acting = $user === null ? null : $this->resolveActivePrincipal($user, $claims);

        if ($claims === null || $user === null || $acting === null) {
            return null;
        }

        $deviceHint = $claims[Claims::DEVICE_ID->value] ?? null;
        $device     = $this->resolveDeviceFromHint($user, $deviceHint);
        $deviceLost = $deviceHint !== null && $device === null;

        // Fail-closed: a did that does not resolve must reject rather than bind
        // null, otherwise audit trails record "no device" despite the token
        // claiming one.
        return $deviceLost
            ? null
            : [
                'identity'  => $user,
                'principal' => $acting[0],
                'tenant'    => $acting[1],
                'device'    => $device,
            ];
    }

    /**
     * Look up the identity for the `sub` claim, which `parse()` guarantees on
     * an access token, and confirm it is active. Stores the retrieved user on
     * `$lastRetrievedUser` even on the inactive/non-Identity branches so
     * `Failed` attributes to the resolved account rather than a null.
     *
     * @param  ?array<string, mixed>  $claims
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function loadIdentityFromClaims(?array $claims): ?Identity
    {
        if ($claims === null) {
            return null;
        }

        $user = $this->provider->retrieveById($claims[Claims::SUBJECT->value]);

        if ($user !== null) {
            $this->lastRetrievedUser = $user;
        }

        if (!$user instanceof Identity || !ActivationPolicy::isActive($user)) {
            return null;
        }

        return $user;
    }

    /**
     * Resolve a principal from the claims and confirm it and its tenant are
     * active, returning the principal with the tenant its activity check
     * loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $user
     * @param  array<string, mixed>  $claims
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Principal, 1: ?\SineMacula\Laravel\Authentication\Contracts\Tenant}|null
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveActivePrincipal(Identity $user, array $claims): ?array
    {
        $principal = $this->resolvePrincipalFromClaims($user, $claims);

        if (!$principal instanceof Principal || !ActivationPolicy::isActive($principal)) {
            return null;
        }

        $tenant = ActivationPolicy::activeTenant($principal);

        return $tenant === false ? null : [$principal, $tenant];
    }

    /**
     * Resolve the principal named by the `pid` claim, which `parse()`
     * guarantees on an access token, failing closed when the resolver returns
     * any other principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array<string, mixed>  $claims
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolvePrincipalFromClaims(Identity $identity, array $claims): ?Principal
    {
        $hint     = $claims[Claims::PRINCIPAL_ID->value];
        $resolved = $this->resolvePrincipal($identity, $hint);

        return $this->matchesPidHint($resolved, $hint) ? $resolved : null;
    }
}
