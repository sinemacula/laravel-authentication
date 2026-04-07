<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Auth\Events\Login;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Jwt\Claims;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;

/**
 * Stateless JWT bearer-token guard.
 *
 * Reads `Authorization: Bearer <token>` from the active request,
 * decodes via `JwtTokenService`, validates payload claims, and binds
 * the resolved identity, principal, and (optional) device.
 *
 * Also exposes `refresh()` for refresh-credential exchange (REQ-03),
 * which rotates the device's stored rotation-id digest on every
 * successful exchange and returns both a new access token and a new
 * refresh token (the old refresh token is burned at the server side).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
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
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     */
    public function __construct(
        string $name,
        IdentityProvider $provider,
        PrincipalResolver $resolver,
        Dispatcher $events,
        Request $request,
        Timebox $timebox,
        // Token service used to decode and issue JWTs.
        protected JwtTokenService $tokens,
        // Database connection resolver used for atomic rotation updates.
        protected ConnectionResolverInterface $connections,
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
     * The exchange:
     *   1. parses the token enforcing signature, expiry, `typ`, issuer,
     *      and audience (via `JwtTokenService::parse()`),
     *   2. loads the device row named by the `did` claim,
     *   3. verifies the token's `jti` against the device's hashed
     *      rotation digest in constant time (`hash_equals`),
     *   4. hydrates the contextual lifecycle from the device's
     *      polymorphic `authenticatable` relation,
     *   5. rotates the rotation id — generates a fresh random value,
     *      overwrites the device's stored digest inside a transaction,
     *   6. issues a new access token and a new refresh token carrying
     *      the freshly minted rotation id,
     *   7. dispatches `Refreshed` on success; dispatches `RefreshFailed`
     *      with a machine-readable reason on any early-return path.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshResult|null
     */
    public function refresh(#[\SensitiveParameter] string $refreshToken): ?RefreshResult
    {
        $decoded = $this->decodeRefreshToken($refreshToken);

        if ($decoded === null) {
            return null;
        }

        [$device, $rotationId] = $decoded;

        $context = $this->hydrateRefreshContext($device);

        if ($context === null) {
            return null;
        }

        [$identity, $principal] = $context;

        return $this->completeRefresh($device, $identity, $principal, $rotationId);
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
     * Look up a device by id through the configured device model class.
     *
     * @param  mixed  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Device|null
     */
    protected function findDeviceById(mixed $id): ?Device
    {
        $class = Config::string('laravel-authentication.device.model');

        if ($class === '') {
            return null;
        }

        /** @var \Illuminate\Database\Eloquent\Model $model */
        $model = new $class;

        $device = $model->newQuery()->find($id);

        return $device instanceof Device ? $device : null;
    }

    /**
     * Persist a new rotation-id digest onto the device row. Runs
     * inside a transaction so a failed write cannot leave the device
     * with an inconsistent refresh credential.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $device
     * @param  string  $rotationId
     * @return void
     */
    protected function rotateDeviceRefreshKey(
        Model $device,
        #[\SensitiveParameter] string $rotationId,
    ): void {
        $column = Config::string('laravel-authentication.device.refresh_key_column', 'refresh_key');
        $digest = RefreshTokenHasher::hash($rotationId);

        $this->connections
            ->connection($device->getConnectionName())
            ->transaction(static function () use ($device, $column, $digest): void {
                $device->forceFill([$column => $digest])->save();
            });
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

        $context = $this->resolveContextFromToken($token);

        if ($context === null) {
            $this->fireFailedEvent(null, []);

            return null;
        }

        $this->setIdentity($context['identity']);
        $this->fireValidatedEvent($context['identity']);
        $this->setPrincipal($context['principal']);

        if ($context['device'] !== null) {
            $this->setDevice($context['device']);
        }

        $this->events->dispatch(new Login($this->name, $context['identity'], false));

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
     * @param  array<string, mixed>|null  $claims
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    private function loadIdentityFromClaims(?array $claims): ?Identity
    {
        if ($claims === null || ($claims[Claims::SUBJECT] ?? null) === null) {
            return null;
        }

        $user = $this->provider->retrieveById($claims[Claims::SUBJECT]);

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
     * Decode a refresh token and pull out the device record + plaintext
     * rotation id. Dispatches `RefreshFailed` and returns `null` on any
     * decode, claim, lookup, or rotation-mismatch failure so the
     * top-level `refresh()` method stays inside the branch budget.
     *
     * @param  string  $refreshToken
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device, 1: string}|null
     */
    private function decodeRefreshToken(#[\SensitiveParameter] string $refreshToken): ?array
    {
        $claims = $this->tokens->parse($refreshToken, Claims::TYPE_REFRESH);

        $extracted = $this->extractRefreshClaims($claims);

        if ($extracted === null) {
            return null;
        }

        [$rawDeviceId, $rotationId] = $extracted;

        $device = $this->loadDeviceForRefresh($rawDeviceId, $rotationId);

        return $device === null ? null : [$device, $rotationId];
    }

    /**
     * Extract and shape-check the refresh-token claims. Dispatches
     * `RefreshFailed` with reason `token_invalid` and returns `null`
     * for any malformed payload.
     *
     * @param  array<string, mixed>|null  $claims
     * @return array{0: mixed, 1: string}|null
     */
    private function extractRefreshClaims(?array $claims): ?array
    {
        if ($claims === null) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_TOKEN_INVALID, null);

            return null;
        }

        $rawDeviceId = $claims[Claims::DEVICE_ID] ?? null;
        $rotationId  = $claims[Claims::JWT_ID]    ?? null;
        $shapeOk     = $rawDeviceId !== null && is_string($rotationId) && $rotationId !== '';

        if (!$shapeOk) {
            $this->dispatchRefreshFailure(
                RefreshFailed::REASON_TOKEN_INVALID,
                is_string($rawDeviceId) ? $rawDeviceId : null,
            );

            return null;
        }

        /** @var non-empty-string $rotationId */
        return [$rawDeviceId, $rotationId];
    }

    /**
     * Load the device row named by the refresh-token's `did` claim and
     * verify the supplied rotation id against its stored digest in
     * constant time. Dispatches `RefreshFailed` with the appropriate
     * reason and returns `null` for any failure path.
     *
     * @param  mixed  $rawDeviceId
     * @param  string  $rotationId
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device)|null
     */
    private function loadDeviceForRefresh(
        mixed $rawDeviceId,
        #[\SensitiveParameter] string $rotationId,
    ): (Device&Model)|null {
        $deviceId = IdentifierCoercion::stringify($rawDeviceId);
        $device   = $this->findDeviceById($rawDeviceId);

        if ($device === null || !$device instanceof Model) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_DEVICE_UNKNOWN, $deviceId);

            return null;
        }

        if (!RefreshTokenHasher::verify($rotationId, $device->getRefreshKey())) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_ROTATION_MISMATCH, $deviceId);

            return null;
        }

        return $device;
    }

    /**
     * Hydrate the contextual lifecycle (identity + principal) from a
     * verified device row. Dispatches `RefreshFailed` and returns
     * `null` on any inactive / unresolved branch.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}|null
     */
    private function hydrateRefreshContext(Device&Model $device): ?array
    {
        $deviceId = IdentifierCoercion::stringify($device->getDeviceIdentifier());

        $identity = $this->resolveRefreshIdentity($device, $deviceId);

        if ($identity === null) {
            return null;
        }

        $principal = $this->resolveRefreshPrincipal($identity, $deviceId);

        return $principal === null ? null : [$identity, $principal];
    }

    /**
     * Validate the device's `authenticatable` relation and confirm the
     * resolved identity is currently active. Dispatches the
     * appropriate `RefreshFailed` reason and returns `null` for any
     * failure path.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?string  $deviceId
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    private function resolveRefreshIdentity(Device&Model $device, ?string $deviceId): ?Identity
    {
        /** @var \SineMacula\Laravel\Authentication\Contracts\Identity|null $identity */
        $identity = $device->getRelationValue('authenticatable');

        if (!$identity instanceof Identity) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_AUTHENTICATABLE_MISSING, $deviceId);

            return null;
        }

        if (!$this->isIdentityActive($identity)) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_IDENTITY_INACTIVE, $deviceId);

            return null;
        }

        return $identity;
    }

    /**
     * Resolve a principal for the refresh-flow identity and verify it
     * is currently active. Dispatches the appropriate `RefreshFailed`
     * reason and returns `null` for any failure path.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $deviceId
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|null
     */
    private function resolveRefreshPrincipal(Identity $identity, ?string $deviceId): ?Principal
    {
        $principal = $this->resolver->resolve($identity);

        if (!$principal instanceof Principal) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_PRINCIPAL_UNRESOLVED, $deviceId);

            return null;
        }

        if (!$principal->isActive()) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_PRINCIPAL_INACTIVE, $deviceId);

            return null;
        }

        return $principal;
    }

    /**
     * Final refresh phase: rotate the device's stored digest, bind the
     * contextual triple on the guard, issue the new token pair, and
     * dispatch the `Refreshed` event.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $oldRotationId
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshResult
     */
    private function completeRefresh(
        Device&Model $device,
        Identity $identity,
        Principal $principal,
        #[\SensitiveParameter] string $oldRotationId,
    ): RefreshResult {
        unset($oldRotationId); // burned by rotation below

        $newRotationId = RefreshTokenHasher::generate();

        $this->rotateDeviceRefreshKey($device, $newRotationId);

        $this->clearContextualState();

        $this->setIdentity($identity);
        $this->setPrincipal($principal);
        $this->setDevice($device);

        $accessToken     = $this->tokens->issueAccessToken($identity, $principal, $device);
        $newRefreshToken = $this->tokens->issueRefreshToken($device, $newRotationId);

        $this->events->dispatch(new Refreshed($this->name, $identity, $principal, $device));

        return new RefreshResult($accessToken, $newRefreshToken);
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
            return $this->resolver->resolve($identity);
        }

        $hint     = $claims[Claims::PRINCIPAL_ID];
        $resolved = $this->resolver->resolve($identity, $hint);

        return $this->matchesPidHint($resolved, $hint) ? $resolved : null;
    }

    /**
     * Confirm that a resolver-returned principal matches the `pid`
     * hint embedded in the access-token claims. Used by the
     * fail-closed pid path so a hint that resolves to a *different*
     * principal is rejected rather than silently downgraded.
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

    /**
     * Dispatch a `RefreshFailed` event — used by every early-return
     * path in the refresh flow so failed exchanges are observable by
     * audit-log consumers without scraping logs.
     *
     * @param  string  $reason
     * @param  ?string  $deviceId
     * @return void
     */
    private function dispatchRefreshFailure(string $reason, ?string $deviceId): void
    {
        $this->events->dispatch(new RefreshFailed($this->name, $reason, $deviceId));
    }
}
