<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Refresh-token exchange service.
 *
 * Encapsulates the entire refresh-credential round trip — parse the
 * refresh token, verify the rotation id against the device's stored
 * digest in constant time, hydrate the contextual lifecycle from the
 * device's polymorphic `authenticatable` relation, rotate the digest
 * server-side inside a database transaction, and issue a new access +
 * refresh token pair.
 *
 * Extracted out of `JwtGuard` so the (security-critical) refresh
 * surface lives in a single, narrowly-scoped class with explicit
 * dependencies. The guard becomes a thin caller that takes the
 * resulting `ExchangedRefresh` and binds the contextual triple onto
 * its own lifecycle.
 *
 * Failure paths dispatch `RefreshFailed` events with machine-readable
 * reason codes so SIEM consumers can attribute failures.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
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
        private readonly JwtTokenService $tokens,
        private readonly ConnectionResolverInterface $connections,
        private readonly Dispatcher $events,
        private readonly PrincipalResolver $resolver,
        private readonly string $guardName,
    ) {}

    /**
     * Exchange a refresh token for a new access + refresh token pair,
     * rotating the device's stored rotation digest in the process.
     *
     * Returns an `ExchangedRefresh` DTO on success carrying the
     * resolved contextual triple plus the new tokens. Returns `null`
     * on any failure path; a `RefreshFailed` event is dispatched
     * with a machine-readable reason code first.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|null
     */
    public function exchange(#[\SensitiveParameter] string $refreshToken): ?ExchangedRefresh
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

        return $this->completeExchange($device, $identity, $principal, $rotationId);
    }

    /**
     * Mark a device as revoked by setting its `revoked_at` timestamp
     * and clearing its stored refresh-key digest. Runs as a raw
     * query-builder update so Eloquent observers do not fire and
     * in-memory model attributes do not leak into the persisted
     * write. Subsequent refresh attempts against this device row
     * will be rejected with reason `device_revoked`.
     *
     * Exposed for consumer code that needs to force-revoke a device
     * out-of-band (logout-everywhere flows, incident response) —
     * the exchange service uses it internally on the reuse-detection
     * path when the atomic rotation CAS affects zero rows.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     */
    public function revokeDevice(Device&Model $device): void
    {
        $refreshKeyColumn = $this->refreshKeyColumn($device);
        $revokedAtColumn  = $this->revokedAtColumn($device);

        $this->connections
            ->connection($device->getConnectionName())
            ->table($device->getTable())
            ->where($device->getKeyName(), $device->getKey())
            ->update([
                $refreshKeyColumn => null,
                $revokedAtColumn  => \Illuminate\Support\Carbon::now(),
            ]);
    }

    /**
     * Decode a refresh token and pull out the device record + plaintext
     * rotation id. Dispatches `RefreshFailed` and returns `null` on
     * any decode, claim, lookup, or rotation-mismatch failure.
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
     * Load the device row named by the refresh-token's `did` claim
     * and verify the supplied rotation id against its stored digest
     * in constant time. Dispatches `RefreshFailed` with the
     * appropriate reason and returns `null` for any failure path.
     *
     * Rejects revoked devices (`revoked_at IS NOT NULL`) and devices
     * that have no refresh credential issued (`refresh_key IS NULL`)
     * before attempting the constant-time verification, so a
     * revoked device row cannot be used to time-probe the valid
     * rotation-id space.
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

        if ($device->getRevokedAt() !== null) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_DEVICE_REVOKED, $deviceId);

            return null;
        }

        $storedDigest = $device->getRefreshKey();

        if ($storedDigest === null || !RefreshTokenHasher::verify($rotationId, $storedDigest)) {
            $this->dispatchRefreshFailure(RefreshFailed::REASON_ROTATION_MISMATCH, $deviceId);

            return null;
        }

        return $device;
    }

    /**
     * Look up a device by id through the configured device model class.
     *
     * @param  mixed  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Device|null
     */
    private function findDeviceById(mixed $id): ?Device
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
     * Validate the device's `authenticatable` relation and confirm
     * the resolved identity is currently active. Dispatches the
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
     * Resolve a principal for the refresh-flow identity and verify
     * it is currently active. Dispatches the appropriate
     * `RefreshFailed` reason and returns `null` for any failure path.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $deviceId
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|null
     */
    private function resolveRefreshPrincipal(Identity $identity, ?string $deviceId): ?Principal
    {
        $principal = $this->safeResolvePrincipal($identity);

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
     * Final exchange phase: atomically rotate the device's stored
     * digest via a compare-and-swap UPDATE, issue the new access +
     * refresh token pair, and assemble the `ExchangedRefresh` DTO.
     * Does NOT bind any state on a guard — the caller (typically
     * `JwtGuard::refresh()`) is responsible for the lifecycle binding.
     *
     * Returns `null` when the CAS affects zero rows — that signals
     * a refresh-token reuse: the token verified against the stored
     * digest earlier in the flow but another concurrent refresh
     * request (or a stolen-token replay) has already rotated the
     * digest in between. The entire device is revoked as a response
     * and a `RefreshFailed` event with reason `rotation_reuse` is
     * dispatched so the caller's `null` return surfaces as a 401.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $oldRotationId
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|null
     */
    private function completeExchange(
        Device&Model $device,
        Identity $identity,
        Principal $principal,
        #[\SensitiveParameter] string $oldRotationId,
    ): ?ExchangedRefresh {
        $newRotationId = RefreshTokenHasher::generate();

        $rotated = $this->atomicallyRotateRefreshKey($device, $oldRotationId, $newRotationId);

        if (!$rotated) {
            $deviceId = IdentifierCoercion::stringify($device->getDeviceIdentifier());

            // The CAS lost to a concurrent rotation — treat it as a
            // refresh-token reuse and revoke the whole device family.
            $this->revokeDevice($device);
            $this->dispatchRefreshFailure(RefreshFailed::REASON_ROTATION_REUSE, $deviceId);

            return null;
        }

        // Reflect the rotation on the in-memory model so any
        // subsequent read on the bound device during this request
        // sees the new digest (not the old one).
        $refreshKeyColumn = $this->refreshKeyColumn($device);
        $device->setAttribute($refreshKeyColumn, RefreshTokenHasher::hash($newRotationId));

        $tokens = new RefreshResult(
            $this->tokens->issueAccessToken($identity, $principal, $device),
            $this->tokens->issueRefreshToken($device, $newRotationId),
        );

        return new ExchangedRefresh($identity, $principal, $device, $tokens);
    }

    /**
     * Rotate the device's stored digest atomically via a single
     * compare-and-swap UPDATE:
     *
     *     UPDATE devices
     *        SET refresh_key = :new_digest
     *      WHERE id = :device_id
     *        AND refresh_key = :old_digest
     *        AND revoked_at IS NULL
     *
     * Returns `true` when exactly one row was affected (the rotation
     * succeeded) and `false` when zero rows were affected (another
     * concurrent rotation or a revocation has changed the row since
     * the original read). The caller interprets `false` as a
     * refresh-token reuse and revokes the device family.
     *
     * The raw query-builder update bypasses Eloquent model events so
     * consumer observers registered against the device do not fire
     * on every refresh — their side effects should trigger on the
     * `Refreshed` package event instead.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $oldRotationId
     * @param  string  $newRotationId
     * @return bool
     */
    private function atomicallyRotateRefreshKey(
        Device&Model $device,
        #[\SensitiveParameter] string $oldRotationId,
        #[\SensitiveParameter] string $newRotationId,
    ): bool {
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
     * Resolve the refresh-key column name for the supplied device,
     * honouring the `ActsAsDevice` trait's public accessor when
     * present (so consumers that remap the column via the trait's
     * override hook are respected) and falling back to the package
     * config otherwise.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return string
     */
    private function refreshKeyColumn(Device $device): string
    {
        if (method_exists($device, 'getRefreshKeyName')) {
            /** @var string $column */
            $column = $device->getRefreshKeyName();

            if ($column !== '') {
                return $column;
            }
        }

        return Config::string('laravel-authentication.device.refresh_key_column', 'refresh_key');
    }

    /**
     * Resolve the revoked-at column name for the supplied device.
     * Honours the `ActsAsDevice` trait's public accessor when
     * present and falls back to the default `'revoked_at'`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return string
     */
    private function revokedAtColumn(Device $device): string
    {
        if (method_exists($device, 'getRevokedAtName')) {
            /** @var string $column */
            $column = $device->getRevokedAtName();

            if ($column !== '') {
                return $column;
            }
        }

        return 'revoked_at';
    }

    /**
     * Resolve a principal for the supplied identity, catching the
     * typed `UnresolvableIdentityException` thrown by the package's
     * default resolver when an identity implements neither `Principal`
     * nor `HasPrincipals`. Returns `null` so the caller surfaces a
     * `RefreshFailed` event rather than propagating a 500.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|null
     */
    private function safeResolvePrincipal(Identity $identity): ?Principal
    {
        try {
            return $this->resolver->resolve($identity);
        } catch (UnresolvableIdentityException) {
            return null;
        }
    }

    /**
     * Whether the supplied identity opts into activation checking
     * and, if it does, whether it currently reports itself active.
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
     * Dispatch a `RefreshFailed` event with the supplied reason and
     * device id. Used by every early-return path in the exchange so
     * failed refreshes are observable by audit-log consumers without
     * scraping logs.
     *
     * @param  string  $reason
     * @param  ?string  $deviceId
     * @return void
     */
    private function dispatchRefreshFailure(string $reason, ?string $deviceId): void
    {
        $this->events->dispatch(new RefreshFailed($this->guardName, $reason, $deviceId));
    }
}
