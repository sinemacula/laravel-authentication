<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Refresh-token exchange service.
 *
 * Encapsulates the refresh round trip: parse the token, verify the rotation id
 * against the device's stored digest in constant time, hydrate the contextual
 * lifecycle from the device's polymorphic `authenticatable` relation, rotate
 * the digest server-side, and issue a new access + refresh token pair.
 *
 * Failure paths dispatch `RefreshFailed` events with machine-readable reason
 * codes for SIEM attribution.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RefreshTokenExchange
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  string  $guardName
     */
    public function __construct(

        /** Token service for parsing and issuing tokens. */
        private readonly JwtTokenService $tokens,

        /** Connection resolver for raw CAS digest rotation. */
        private readonly ConnectionResolverInterface $connections,

        /** Event dispatcher for RefreshFailed events. */
        private readonly Dispatcher $events,

        /** Resolver mapping identity to acting principal. */
        private PrincipalResolver $resolver,

        /** Guard name carried on every RefreshFailed event. */
        private readonly string $guardName,

    ) {}

    /**
     * Rebind the principal resolver used by refresh exchanges.
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
     * Exchange a refresh token for a new access + refresh token pair, rotating
     * the device's stored digest. Returns `null` on any failure path; a
     * `RefreshFailed` event is dispatched first.
     *
     * @param  string  $refreshToken
     * @return ?\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration
     */
    public function exchange(#[\SensitiveParameter] string $refreshToken): ?ExchangedRefresh
    {
        $decoded = $this->decodeRefreshToken($refreshToken);

        if ($decoded === null) {
            return null;
        }

        [$device, $rotationId, $principalHint] = $decoded;

        $context = $this->hydrateRefreshContext($device, $principalHint);

        if ($context === null) {
            return null;
        }

        [$identity, $principal] = $context;

        return $this->completeExchange($device, $identity, $principal, $rotationId);
    }

    /**
     * Mark a device revoked by setting its `revoked_at` and clearing its
     * refresh-key digest. Uses a raw query-builder update so Eloquent observers
     * do not fire and in-memory attributes do not leak into the persisted
     * write.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return void
     */
    public function revokeDevice(EloquentDevice&Model $device): void
    {
        $refreshKeyColumn = $this->refreshKeyColumn($device);
        $revokedAtColumn  = $this->revokedAtColumn($device);

        $this->connections
            ->connection($device->getConnectionName())
            ->table($device->getTable())
            ->where($device->getKeyName(), $device->getKey())
            ->update([
                $refreshKeyColumn => null,
                $revokedAtColumn  => Carbon::now(),
            ]);
    }

    /**
     * Decode a refresh token and return the device + plaintext rotation id.
     * Dispatches `RefreshFailed` and returns `null` on any failure.
     *
     * @formatter:off
     *
     * @param  string  $refreshToken
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice, 1: string, 2: mixed}|null
     *
     * @formatter:on
     */
    private function decodeRefreshToken(#[\SensitiveParameter] string $refreshToken): ?array
    {
        $claims = $this->tokens->parse($refreshToken, TokenType::REFRESH);

        $extracted = $this->extractRefreshClaims($claims);

        if ($extracted === null) {
            return null;
        }

        [$rawDeviceId, $rotationId, $principalHint] = $extracted;

        $device = $this->loadDeviceForRefresh($rawDeviceId, $rotationId);

        return $device === null ? null : [$device, $rotationId, $principalHint];
    }

    /**
     * Extract and shape-check the refresh-token claims. Dispatches
     * `token_invalid` and returns `null` for any malformed payload.
     *
     * @param  ?array<string, mixed>  $claims
     * @return array{0: mixed, 1: string, 2: mixed}|null
     */
    private function extractRefreshClaims(#[\SensitiveParameter] ?array $claims): ?array
    {
        if ($claims === null) {

            $this->dispatchRefreshFailure(RefreshFailureReason::TOKEN_INVALID, null);

            return null;
        }

        $rawDeviceId   = $claims[Claims::DEVICE_ID->value]    ?? null;
        $rotationId    = $claims[Claims::JWT_ID->value]       ?? null;
        $principalHint = $claims[Claims::PRINCIPAL_ID->value] ?? null;
        $shapeOk       = $rawDeviceId !== null && is_string($rotationId) && $rotationId !== '';

        if (!$shapeOk) {

            $this->dispatchRefreshFailure(
                RefreshFailureReason::TOKEN_INVALID,
                is_string($rawDeviceId) ? $rawDeviceId : null,
            );

            return null;
        }

        /** @var non-empty-string $rotationId */
        return [$rawDeviceId, $rotationId, $principalHint];
    }

    /**
     * Dispatch a `RefreshFailed` event with the supplied reason and device id.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason  $reason
     * @param  ?string  $deviceId
     * @return void
     */
    private function dispatchRefreshFailure(RefreshFailureReason $reason, ?string $deviceId): void
    {
        $this->events->dispatch(new RefreshFailed($this->guardName, $reason, $deviceId));
    }

    /**
     * Load the device named by the `did` claim and verify the supplied rotation
     * id against its stored digest in constant time.
     *
     * Rejects revoked devices and devices with no refresh credential before the
     * constant-time verification, so a revoked row cannot be used to time-probe
     * the valid rotation-id space.
     *
     * @param  mixed  $rawDeviceId
     * @param  string  $rotationId
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     */
    private function loadDeviceForRefresh(mixed $rawDeviceId, #[\SensitiveParameter] string $rotationId): (EloquentDevice&Model)|null
    {
        $deviceId = IdentifierCoercion::stringify($rawDeviceId);
        $device   = $this->findDeviceById($rawDeviceId);

        if ($device === null) {

            $this->dispatchRefreshFailure(RefreshFailureReason::DEVICE_UNKNOWN, $deviceId);

            return null;
        }

        if ($device->getRevokedAt() !== null) {

            $this->dispatchRefreshFailure(RefreshFailureReason::DEVICE_REVOKED, $deviceId);

            return null;
        }

        $storedDigest = $device->getRefreshKey();

        if ($storedDigest === null || !RefreshTokenHasher::verify($rotationId, $storedDigest)) {

            $this->dispatchRefreshFailure(RefreshFailureReason::ROTATION_MISMATCH, $deviceId);

            return null;
        }

        return $device;
    }

    /**
     * Look up a device by id through the configured device model class.
     *
     * @param  mixed  $id
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration
     */
    private function findDeviceById(mixed $id): (EloquentDevice&Model)|null
    {
        $class = $this->configuredDeviceModelClass();

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice $model */
        $model = new $class;

        $device = $model->newQuery()->find($id);

        if (!$device instanceof Model || !$device instanceof EloquentDevice) {
            return null;
        }

        return $device;
    }

    /**
     * Resolve the configured device model class and validate that it satisfies
     * the explicit Eloquent-backed persistence boundary.
     *
     * @formatter:off
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice>
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration
     */
    private function configuredDeviceModelClass(): string
    {
        $class = Config::string('authentication.device.model', '');

        InvalidDeviceModelConfiguration::validate($class);

        /** @var class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice> $class */
        return $class;
    }

    /**
     * Hydrate identity + principal from a verified device row.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  mixed  $principalHint
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}|null
     *
     * @formatter:on
     */
    private function hydrateRefreshContext(EloquentDevice&Model $device, mixed $principalHint): ?array
    {
        $deviceId = IdentifierCoercion::stringify($device->getDeviceIdentifier());

        $identity = $this->resolveRefreshIdentity($device, $deviceId);

        if ($identity === null) {
            return null;
        }

        $principal = $this->resolveRefreshPrincipal($identity, $deviceId, $principalHint);

        return $principal === null ? null : [$identity, $principal];
    }

    /**
     * Validate the device's `authenticatable` relation and confirm the resolved
     * identity is currently active.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  ?string  $deviceId
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function resolveRefreshIdentity(EloquentDevice&Model $device, ?string $deviceId): ?Identity
    {
        /** @var ?\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = $device->getRelationValue('authenticatable');

        if (!$identity instanceof Identity) {

            $this->dispatchRefreshFailure(RefreshFailureReason::AUTHENTICATABLE_MISSING, $deviceId);

            return null;
        }

        if (!$this->isIdentityActive($identity)) {

            $this->dispatchRefreshFailure(RefreshFailureReason::IDENTITY_INACTIVE, $deviceId);

            return null;
        }

        return $identity;
    }

    /**
     * Whether the identity opts into activation checking and, if it does,
     * whether it currently reports active.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    private function isIdentityActive(Identity $identity): bool
    {
        if (!$identity instanceof CanBeActive) {
            return true;
        }

        return $identity->isActive();
    }

    /**
     * Resolve a principal for the refresh-flow identity and verify it is
     * currently active.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $deviceId
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function resolveRefreshPrincipal(Identity $identity, ?string $deviceId, mixed $hint = null): ?Principal
    {
        $hintProvided = $hint !== null;
        $principal    = $this->safeResolvePrincipal($identity, $hint);

        if ($hintProvided && !$this->matchesPidHint($principal, $hint)) {

            $this->dispatchRefreshFailure(RefreshFailureReason::PRINCIPAL_MISMATCH, $deviceId);

            return null;
        }

        if (!$principal instanceof Principal) {

            $this->dispatchRefreshFailure(RefreshFailureReason::PRINCIPAL_UNRESOLVED, $deviceId);

            return null;
        }

        if (!$principal->isActive()) {

            $this->dispatchRefreshFailure(RefreshFailureReason::PRINCIPAL_INACTIVE, $deviceId);

            return null;
        }

        return $principal;
    }

    /**
     * Resolve a principal for the identity, catching
     * `UnresolvableIdentityException` and returning `null` so the caller
     * surfaces `RefreshFailed` rather than a 500.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function safeResolvePrincipal(Identity $identity, mixed $hint = null): ?Principal
    {
        try {
            return $hint === null
                ? $this->resolver->resolve($identity)
                : $this->resolver->resolve($identity, $hint);
        } catch (UnresolvableIdentityException) {
            return null;
        }
    }

    /**
     * Confirm a resolver-returned principal matches the `pid` hint.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $resolved
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
     * Atomically rotate the digest via a compare-and-swap UPDATE, issue the new
     * tokens, and assemble the DTO. Does NOT bind any state on a guard.
     *
     * Returns `null` when the CAS affects zero rows: the token verified earlier
     * but a concurrent refresh (or a stolen-token replay) has rotated the
     * digest in between. The whole device is revoked and `rotation_reuse` is
     * dispatched.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $oldRotationId
     * @return ?\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \Random\RandomException
     */
    private function completeExchange(EloquentDevice&Model $device, Identity $identity, Principal $principal, #[\SensitiveParameter] string $oldRotationId): ?ExchangedRefresh
    {
        $newRotationId = RefreshTokenHasher::generate();

        $rotated = $this->atomicallyRotateRefreshKey($device, $oldRotationId, $newRotationId);

        if (!$rotated) {

            $deviceId = IdentifierCoercion::stringify($device->getDeviceIdentifier());

            // CAS lost: concurrent rotation or reuse. Revoke the device family.
            $this->revokeDevice($device);
            $this->dispatchRefreshFailure(RefreshFailureReason::ROTATION_REUSE, $deviceId);

            return null;
        }

        // Reflect the rotation on the in-memory model so subsequent reads
        // during this request see the new digest.
        $refreshKeyColumn = $this->refreshKeyColumn($device);
        $device->setAttribute($refreshKeyColumn, RefreshTokenHasher::hash($newRotationId));

        $tokens = new RefreshResult(
            $this->tokens->issueAccessToken($identity, $principal, $device),
            $this->tokens->issueRefreshToken($device, $newRotationId, $principal),
        );

        return new ExchangedRefresh($identity, $principal, $device, $tokens);
    }

    /**
     * Rotate the device's stored digest via a single compare-and-swap UPDATE
     * keyed on the device id, the old digest, and a null `revoked_at`. Returns
     * `true` when exactly one row was affected. `false` signals a concurrent
     * rotation or revocation and the caller treats it as refresh reuse.
     *
     * Raw query-builder update bypasses Eloquent events; consumer side effects
     * should trigger on the `Refreshed` package event.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $oldRotationId
     * @param  string  $newRotationId
     * @return bool
     */
    private function atomicallyRotateRefreshKey(EloquentDevice&Model $device, #[\SensitiveParameter] string $oldRotationId, #[\SensitiveParameter] string $newRotationId): bool
    {
        $column     = $this->refreshKeyColumn($device);
        $revokedCol = $this->revokedAtColumn($device);

        $oldDigest = RefreshTokenHasher::hash($oldRotationId);
        $newDigest = RefreshTokenHasher::hash($newRotationId);

        $affected = $this->connections
            ->connection($device->getConnectionName())
            ->table($device->getTable())
            ->where($device->getKeyName(), $device->getKey())
            ->where($column, $oldDigest)
            ->whereNull($revokedCol)
            ->update([$column => $newDigest]);

        return $affected === 1;
    }

    /**
     * Resolve the refresh-key column for the device via the explicit
     * `EloquentDevice` column-name contract.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return string
     */
    private function refreshKeyColumn(EloquentDevice $device): string
    {
        $column = $device->getRefreshKeyName();

        return $column === '' ? 'refresh_key' : $column;
    }

    /**
     * Resolve the revoked-at column for the device via the explicit
     * `EloquentDevice` column-name contract.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return string
     */
    private function revokedAtColumn(EloquentDevice $device): string
    {
        $column = $device->getRevokedAtName();

        return $column === '' ? 'revoked_at' : $column;
    }
}
