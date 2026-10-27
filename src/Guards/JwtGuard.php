<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
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
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Support\Timebox  $timebox
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange  $exchange
     * @param  \Closure(\SineMacula\Laravel\Authentication\Guards\JwtGuard): \SineMacula\Laravel\Authentication\Sessions\SessionService  $sessionFactory
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

        /** Builds the guard's session service the first time it is asked for. */
        private readonly \Closure $sessionFactory,
    ) {
        parent::__construct($name, $provider, $resolver, $events, $request, $timebox);
    }

    /**
     * Return the guard's session service, which signs in, creates or continues
     * the device, and issues the first token pair. Built once per guard; it
     * reads the guard's request, dispatcher, provider and resolver each time it
     * runs, so it follows their rebinds.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    public function sessions(): SessionService
    {
        return $this->sessions ??= ($this->sessionFactory)($this);
    }

    /**
     * Exchange a refresh token for a new access token + rotated refresh token.
     *
     * Delegates the round trip to `RefreshTokenExchange`, binds the resolved
     * contextual triple, and dispatches `Refreshed`. Returns `null` on failure;
     * the exchange has already dispatched `RefreshFailed` with a reason code.
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
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function refresh(#[\SensitiveParameter] string $refreshToken): ?RefreshResult
    {
        $this->fireAttemptingEvent([]);

        $result = $this->exchange->exchange($refreshToken);

        if ($result === null) {

            $this->fireFailedEvent(null, []);

            return null;
        }

        // Route through login() so refresh fires the same event sequence as
        // attempt(). Refreshed fires afterwards so consumers can distinguish a
        // rotation.
        $this->login($result->identity, $result->principal, $result->device);

        $this->events->dispatch(
            new Refreshed(
                $this->name,
                $result->identity,
                $result->principal,
                $result->device,
            ),
        );

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
     * `Event::fake()`) receives `RefreshFailed` as well as the guard's events.
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

        $this->login($context['identity'], $context['principal'], $context['device']);

        return $context['identity'];
    }

    /**
     * Resolve identity, principal, and device from a parsed bearer token. The
     * caller fires `Failed` and binds state.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $token
     * @return array{identity: \SineMacula\Laravel\Authentication\Contracts\Identity, principal: \SineMacula\Laravel\Authentication\Contracts\Principal, device: ?\SineMacula\Laravel\Authentication\Contracts\Device}|null
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveContextFromToken(#[\SensitiveParameter] string $token): ?array
    {
        $claims    = $this->tokens->parse($token, TokenType::ACCESS);
        $user      = $this->loadIdentityFromClaims($claims);
        $principal = $user === null ? null : $this->resolveActivePrincipal($user, $claims);

        if ($claims === null || $user === null || $principal === null) {
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
                'principal' => $principal,
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
     * active.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $user
     * @param  array<string, mixed>  $claims
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveActivePrincipal(Identity $user, array $claims): ?Principal
    {
        $principal = $this->resolvePrincipalFromClaims($user, $claims);

        return $principal instanceof Principal && ActivationPolicy::isPrincipalActive($principal) ? $principal : null;
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
