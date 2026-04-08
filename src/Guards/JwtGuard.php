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
use SineMacula\Laravel\Authentication\Jwt\Claims;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;

/**
 * Stateless JWT bearer-token guard.
 *
 * Reads `Authorization: Bearer <token>` from the active request,
 * decodes via `JwtTokenService`, validates payload claims, and binds
 * the resolved identity, principal, and (optional) device.
 *
 * Also exposes `refresh()` for refresh-credential exchange (REQ-03).
 * The refresh flow itself is delegated to `RefreshTokenExchange` —
 * this guard is a thin lifecycle adapter that binds the resulting
 * contextual triple and dispatches the `Refreshed` event.
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
        string $name,
        IdentityProvider $provider,
        PrincipalResolver $resolver,
        Dispatcher $events,
        Request $request,
        Timebox $timebox,
        // Token service used to decode and issue JWTs on the access-token path.
        protected JwtTokenService $tokens,
        // Refresh-credential exchange service — owns the entire refresh
        // round trip.
        protected RefreshTokenExchange $exchange,
    ) {
        parent::__construct($name, $provider, $resolver, $events, $request, $timebox);
    }

    /**
     * Return the authenticated identity bound to the guard, resolving
     * it from the request's bearer token if necessary.
     *
     * Fires the standard `Attempting` and `Failed` events on the
     * bearer-token resolution path so SIEM pipelines can observe
     * failed authentications the same way they observe credential
     * attempts on the BasicGuard. On success, the identity →
     * principal → device lifecycle fires the usual custom events
     * (`Authenticated`, `PrincipalAssigned`, `DeviceAuthenticated`).
     *
     * Fail-closed semantics: a token that claims a specific `pid` or
     * `did` but does not resolve to that exact principal/device is
     * rejected rather than silently downgraded to a default principal
     * and a null device — a silent downgrade is a privilege-confusion
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
     * Exchange a refresh token for a new access token + rotated
     * refresh token.
     *
     * Delegates the entire round trip (parse, verify, hydrate,
     * rotate, issue) to `RefreshTokenExchange`, then binds the
     * resolved contextual triple onto the guard and dispatches the
     * `Refreshed` event. Returns `null` on any failure path — the
     * exchange service has already dispatched `RefreshFailed` with a
     * machine-readable reason code before returning `null`.
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

        // Route through login() so the refresh flow fires the same
        // standard Laravel event sequence as `attempt()` and the
        // bearer-resolution path — `Validated` → `Login` →
        // `Authenticated` → `PrincipalAssigned` → `DeviceAuthenticated`.
        // Consumers listening to `Login` for "session started"
        // semantics (audit-log writes, analytics, rate-limit resets,
        // etc.) observe every refresh the same way they observe a
        // fresh credential login. The package-specific `Refreshed`
        // event fires afterwards carrying the rotated triple so
        // refresh-aware consumers can distinguish a rotation from a
        // first login.
        $this->login($result->identity, $result->principal, $result->device);

        $this->events->dispatch(new Refreshed(
            $this->name,
            $result->identity,
            $result->principal,
            $result->device,
        ));

        return $result->tokens;
    }

    /**
     * Resolve a device record for the identity from a hint (typically a
     * device id from the access-token payload). Returns null when the
     * identity does not implement `HasDevices` or the device is not found.
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
     * Decode a bearer token, fire the success-path events, and bind
     * identity/principal/device on the guard. Returns the bound
     * identity on success or `null` after firing `Failed`.
     *
     * Single entry-and-exit helper extracted from `user()` so the
     * top-level method stays within the project's branch budget.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    private function resolveBearerToken(#[\SensitiveParameter] string $token): ?Identity
    {
        $this->fireAttemptingEvent([]);

        // Reset the tracker so a prior request's user cannot leak
        // onto this failure path.
        $this->lastRetrievedUser = null;

        $context = $this->resolveContextFromToken($token);

        if ($context === null) {
            // `lastRetrievedUser` carries the identity loaded from
            // the `sub` claim whenever `loadIdentityFromClaims()` got
            // that far — so SIEM consumers observe a Failed event
            // with the resolved account name on inactive-identity,
            // principal-unresolved, and device-missing branches, not
            // a null that silently loses attribution.
            $this->fireFailedEvent($this->lastRetrievedUser, []);

            return null;
        }

        $this->login($context['identity'], $context['principal'], $context['device']);

        return $context['identity'];
    }

    /**
     * Resolve identity, principal, and device from a parsed bearer
     * token, returning `null` on any validation failure. The caller
     * is responsible for firing `Failed` and binding state on success.
     *
     * @param  string  $token
     * @return array{
     *     identity: \SineMacula\Laravel\Authentication\Contracts\Identity,
     *     principal: \SineMacula\Laravel\Authentication\Contracts\Principal,
     *     device: \SineMacula\Laravel\Authentication\Contracts\Device|null,
     * }|null
     */
    private function resolveContextFromToken(#[\SensitiveParameter] string $token): ?array
    {
        $claims    = $this->tokens->parse($token, Claims::TYPE_ACCESS);
        $user      = $this->loadIdentityFromClaims($claims);
        $principal = $user === null ? null : $this->resolveActivePrincipal($user, $claims);

        if ($claims === null || $user === null || $principal === null) {
            return null;
        }

        $deviceHint = $claims[Claims::DEVICE_ID] ?? null;
        $device     = $this->resolveDeviceFromHint($user, $deviceHint);
        $deviceLost = $deviceHint !== null && $device === null;

        // Fail-closed: if the token carried a `did` but we could not
        // resolve that exact device, reject rather than bind with a
        // null device. Otherwise audit trails will record the request
        // as "no device" despite the token claiming one.
        return $deviceLost ? null : [
            'identity'  => $user,
            'principal' => $principal,
            'device'    => $device,
        ];
    }

    /**
     * Look up the identity for an access-token's `sub` claim and
     * confirm it is currently active. Returns `null` for missing /
     * non-Identity / inactive identities.
     *
     * When the `sub` claim does resolve (even if the resulting user
     * is not an `Identity` or reports inactive), the retrieved user
     * is stored on `$this->lastRetrievedUser` so the bearer-failure
     * path can attribute the `Failed` event to that specific
     * account rather than dispatching with a `null` user.
     *
     * @param  array<string, mixed>|null  $claims
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    private function loadIdentityFromClaims(?array $claims): ?Identity
    {
        if ($claims === null || ($claims[Claims::SUBJECT] ?? null) === null) {
            return null;
        }

        $user = $this->provider->retrieveById($claims[Claims::SUBJECT]);

        // Track the retrieved user for the Failed-event attribution
        // path even on the inactive/non-Identity branches. Only the
        // `null` branch (no matching `sub`) leaves the tracker at
        // its default `null` value.
        if ($user !== null) {
            $this->lastRetrievedUser = $user;
        }

        if (!$user instanceof Identity || !$this->isIdentityActive($user)) {
            return null;
        }

        return $user;
    }

    /**
     * Resolve a principal for the identity from the access-token claims
     * and confirm it reports `isActive() === true`. Returns `null` for
     * any failure path.
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
     * Resolve a principal for the identity from the token claims,
     * preserving fail-closed semantics on a present-but-unresolvable
     * `pid` hint.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|null
     */
    private function resolvePrincipalFromClaims(Identity $identity, array $claims): ?Principal
    {
        $hintProvided = array_key_exists(Claims::PRINCIPAL_ID, $claims)
            && $claims[Claims::PRINCIPAL_ID] !== null;

        if (!$hintProvided) {
            return $this->safeResolvePrincipal($identity);
        }

        $hint     = $claims[Claims::PRINCIPAL_ID];
        $resolved = $this->safeResolvePrincipal($identity, $hint);

        return $this->matchesPidHint($resolved, $hint) ? $resolved : null;
    }

    /**
     * Confirm that a resolver-returned principal matches the `pid`
     * hint embedded in the access-token claims. Used by the
     * fail-closed pid path so a hint that resolves to a *different*
     * principal is rejected rather than silently downgraded.
     *
     * Fail-closed semantics on unsaved principals: if the resolved
     * principal's identifier stringifies to `null` (typically an
     * unsaved Eloquent model returned by a misbehaving custom
     * `PrincipalResolver`), the match returns `false` and the
     * request is rejected as if the `pid` did not match. This is
     * intentional — the guard cannot securely attribute the token
     * to an unpersisted principal, so the conservative response is
     * to refuse the authentication rather than silently bind a
     * transient actor.
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
