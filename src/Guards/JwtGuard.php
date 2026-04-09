<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;

/**
 * Stateless JWT bearer-token guard.
 *
 * Reads `Authorization: Bearer <token>` from the active request, decodes via
 * `JwtTokenService`, validates claims, and binds the resolved identity,
 * principal, and optional device.
 *
 * Exposes `refresh()` for refresh-credential exchange; the round trip is
 * delegated to `RefreshTokenExchange`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class JwtGuard extends AbstractGuard
{
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

        /** JWT token service used to parse, verify, and issue access and refresh tokens. */
        protected JwtTokenService $tokens,

        /** Refresh-token exchange that rotates credentials and fires the `Refreshed` event. */
        protected RefreshTokenExchange $exchange,

    ) {
        parent::__construct($name, $provider, $resolver, $events, $request, $timebox);
    }

    /**
     * Return the authenticated identity, resolving it from the request's bearer
     * token if necessary.
     *
     * Fail-closed semantics: a token that claims a specific `pid` or `did` but
     * does not resolve to that exact principal/device is rejected rather than
     * silently downgraded - a silent downgrade is a privilege-confusion
     * vulnerability.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    #[\Override]
    public function user(): ?Identity
    {
        if ($this->identity !== null) {
            return $this->identity;
        }

        $token = $this->request->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        return $this->resolveBearerToken($token);
    }

    /**
     * Exchange a refresh token for a new access token + rotated refresh token.
     *
     * Delegates the round trip to `RefreshTokenExchange`, binds the resolved
     * contextual triple, and dispatches `Refreshed`. Returns `null` on failure;
     * the exchange has already dispatched `RefreshFailed` with a reason code.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshResult|null
     */
    public function refresh(#[\SensitiveParameter] string $refreshToken): ?RefreshResult
    {
        $this->fireAttemptingEvent([]);

        $result = $this->exchange->exchange($refreshToken);

        if ($result === null) {
            $this->fireFailedEvent(null, []);

            return null;
        }

        // Route through login() so refresh fires the same Laravel event
        // sequence as attempt(): Validated -> Login -> Authenticated ->
        // PrincipalAssigned -> DeviceAuthenticated. The package-specific
        // Refreshed event fires afterwards so refresh-aware consumers can
        // distinguish a rotation.
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
     * Resolve a device for the identity from a hint (typically the `did`
     * claim). Returns null when the identity does not implement `HasDevices` or
     * the device is not found.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return \SineMacula\Laravel\Authentication\Contracts\Device|null
     */
    protected function resolveDeviceFromHint(Identity $identity, mixed $hint): ?Device
    {
        if ($hint === null || !$identity instanceof HasDevices) {
            return null;
        }

        $device = $identity->devices()->find($hint);

        return $device instanceof Device ? $device : null;
    }

    /**
     * Decode a bearer token, fire success events, and bind
     * identity/principal/device. Returns the bound identity, or `null` after
     * firing `Failed`.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    private function resolveBearerToken(#[\SensitiveParameter] string $token): ?Identity
    {
        $this->fireAttemptingEvent([]);

        // Reset so a prior request's user cannot leak onto this failure path.
        $this->lastRetrievedUser = null;

        $context = $this->resolveContextFromToken($token);

        if ($context === null) {
            // lastRetrievedUser carries the identity loaded from the sub claim
            // whenever loadIdentityFromClaims() got that far, so Failed
            // attributes to the resolved account on the
            // inactive/unresolved/device-missing branches.
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
     * @param  string  $token
     * @return array{identity: \SineMacula\Laravel\Authentication\Contracts\Identity, principal: \SineMacula\Laravel\Authentication\Contracts\Principal, device: \SineMacula\Laravel\Authentication\Contracts\Device|null}|null
     *
     * @formatter:on
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

        // Fail-closed: if the token carried a did but we could not resolve that
        // exact device, reject rather than bind null; otherwise audit trails
        // record "no device" despite the token claiming one.
        return $deviceLost
            ? null
            : [
                'identity'  => $user,
                'principal' => $principal,
                'device'    => $device,
            ];
    }

    /**
     * Look up the identity for the `sub` claim and confirm it is active. Stores
     * the retrieved user on `$lastRetrievedUser` even on the
     * inactive/non-Identity branches so `Failed` attributes to the resolved
     * account rather than a null.
     *
     * @param  array<string, mixed>|null  $claims
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    private function loadIdentityFromClaims(?array $claims): ?Identity
    {
        if ($claims === null || ($claims[Claims::SUBJECT->value] ?? null) === null) {
            return null;
        }

        $user = $this->provider->retrieveById($claims[Claims::SUBJECT->value]);

        // Track the retrieved user for Failed-event attribution even on the
        // inactive/non-Identity branches.
        if ($user !== null) {
            $this->lastRetrievedUser = $user;
        }

        if (!$user instanceof Identity || !$this->isIdentityActive($user)) {
            return null;
        }

        return $user;
    }

    /**
     * Resolve a principal from the claims and confirm it is active.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $user
     * @param  array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|null
     */
    private function resolveActivePrincipal(Identity $user, array $claims): ?Principal
    {
        $principal = $this->resolvePrincipalFromClaims($user, $claims);

        return $principal instanceof Principal && $principal->isActive() ? $principal : null;
    }

    /**
     * Resolve a principal from the claims, preserving fail-closed semantics on
     * a present-but-unresolvable `pid` hint.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|null
     */
    private function resolvePrincipalFromClaims(Identity $identity, array $claims): ?Principal
    {
        $hintProvided = array_key_exists(Claims::PRINCIPAL_ID->value, $claims)
            && $claims[Claims::PRINCIPAL_ID->value] !== null;

        if (!$hintProvided) {
            return $this->safeResolvePrincipal($identity);
        }

        $hint     = $claims[Claims::PRINCIPAL_ID->value];
        $resolved = $this->safeResolvePrincipal($identity, $hint);

        return $this->matchesPidHint($resolved, $hint) ? $resolved : null;
    }

    /**
     * Confirm a resolver-returned principal matches the `pid` hint. Used by the
     * fail-closed pid path so a hint that resolves to a different principal is
     * rejected rather than silently downgraded.
     *
     * Fail-closed on unsaved principals: if the resolved id stringifies to
     * `null` (an unsaved model returned by a misbehaving custom resolver), the
     * match returns `false` so the guard does not bind a transient actor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal|null  $resolved
     * @param  mixed  $hint
     * @return bool
     */
    private function matchesPidHint(?Principal $resolved, mixed $hint): bool
    {
        if ($resolved === null) {
            return false;
        }

        $resolvedId = IdentifierCoercion::stringify($resolved->getPrincipalIdentifier());
        $hintId     = IdentifierCoercion::stringify($hint);

        return $resolvedId !== null && $hintId !== null && hash_equals($resolvedId, $hintId);
    }
}
