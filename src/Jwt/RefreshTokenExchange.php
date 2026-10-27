<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;

/**
 * Refresh-token exchange service.
 *
 * Encapsulates the refresh round trip: parse the token, verify the rotation id
 * against the device's stored digest in constant time, reload the device's
 * owner through the guard's identity provider (so the provider's scopes apply
 * and an owner the guard does not serve is rejected), resolve the principal,
 * rotate the digest server-side, and issue a new access + refresh token pair.
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
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  string  $guardName
     */
    public function __construct(

        /** Token service for parsing and issuing tokens. */
        private readonly JwtTokenService $tokens,

        /** The guard's identity provider, which reloads the device owner. */
        private readonly IdentityProvider $provider,

        /** Connection resolver for raw CAS digest rotation. */
        private readonly ConnectionResolverInterface $connections,

        /** Event dispatcher for RefreshFailed events. */
        private Dispatcher $events,

        /** Resolver mapping identity to acting principal. */
        private PrincipalResolver $resolver,

        /** Guard name carried on every RefreshFailed event. */
        private readonly string $guardName,
    ) {}

    /**
     * Rebind the principal resolver used by refresh exchanges.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @return self
     */
    public function setPrincipalResolver(PrincipalResolver $resolver): self
    {
        $this->resolver = $resolver;

        return $this;
    }

    /**
     * Rebind the event dispatcher that receives `RefreshFailed`, so a
     * dispatcher swapped in after the guard resolved (e.g. `Event::fake()`)
     * receives the exchange's events as well as the guard's.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return self
     */
    public function setDispatcher(Dispatcher $events): self
    {
        $this->events = $events;

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
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function exchange(#[\SensitiveParameter] string $refreshToken): ?ExchangedRefresh
    {
        $claims = $this->extractRefreshClaims($this->tokens->parse($refreshToken, TokenType::REFRESH));

        if ($claims === null) {
            return null;
        }

        [$rawDeviceId, $rotationId, $principalHint] = $claims;

        $now     = CarbonImmutable::now()->startOfSecond();
        $session = $this->loadDeviceForRefresh($rawDeviceId, $rotationId, $now);

        if ($session === null) {
            return null;
        }

        [$device, $absolute] = $session;

        $context = $this->hydrateRefreshContext($device, $principalHint);

        if ($context === null) {
            return null;
        }

        [$identity, $principal] = $context;

        return $this->completeExchange($device, $identity, $principal, $rotationId, $now, $absolute);
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
     * Extract and shape-check the refresh-token claims. `parse()` has already
     * rejected a token missing `did` or `jti`, so what remains is a `jti` that
     * is not a string. Dispatches `token_invalid` and returns `null` for any
     * malformed payload.
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

        $rawDeviceId   = $claims[Claims::DEVICE_ID->value];
        $rotationId    = $claims[Claims::JWT_ID->value];
        $principalHint = $claims[Claims::PRINCIPAL_ID->value] ?? null;

        if (!is_string($rotationId)) {

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
     * id against its stored digest in constant time. Returns the device with
     * its absolute deadline, which the rotation keeps.
     *
     * Rejects revoked devices, devices whose session has ended at `$now` (past
     * either deadline, or without deadlines), and devices with no refresh
     * credential before the constant-time verification, so such a row cannot be
     * used to time-probe the valid rotation-id space. An ended session is not
     * revoked: it simply cannot be refreshed.
     *
     * The revocation time, the deadlines, and the digest are read inside
     * `WriteConnection::during()` for the device, so a device that derives any
     * of them from a relation or another table reads it from the writer as
     * well.
     *
     * @formatter:off
     *
     * @param  mixed  $rawDeviceId
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice, 1: \Carbon\CarbonInterface}|null
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function loadDeviceForRefresh(mixed $rawDeviceId, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now): ?array
    {
        $deviceId = IdentifierCoercion::stringify($rawDeviceId);
        $device   = $this->findDeviceById($rawDeviceId);

        if ($device === null) {

            $this->dispatchRefreshFailure(RefreshFailureReason::DEVICE_UNKNOWN, $deviceId);

            return null;
        }

        $outcome = WriteConnection::during($device, static function () use ($device, $rotationId, $now): CarbonInterface|RefreshFailureReason {

            if ($device->getRevokedAt() !== null) {
                return RefreshFailureReason::DEVICE_REVOKED;
            }

            $deadlines = TokenLifetimes::liveDeadlines($device, $now);

            if ($deadlines === null) {
                return RefreshFailureReason::SESSION_EXPIRED;
            }

            return self::matchesCurrentRotation($device, $rotationId) ? $deadlines[1] : RefreshFailureReason::ROTATION_MISMATCH;
        });

        if ($outcome instanceof RefreshFailureReason) {

            $this->dispatchRefreshFailure($outcome, $deviceId);

            return null;
        }

        return [$device, $outcome];
    }

    /**
     * Whether the rotation id is the device's current one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $rotationId
     * @return bool
     */
    private static function matchesCurrentRotation(EloquentDevice $device, #[\SensitiveParameter] string $rotationId): bool
    {
        $storedDigest = $device->getRefreshKey();

        return $storedDigest !== null && RefreshTokenHasher::verify($rotationId, $storedDigest);
    }

    /**
     * Look up a device by id through the configured device model class, which
     * must satisfy the explicit Eloquent-backed `EloquentDevice` boundary,
     * reading from the write connection so a lagging replica cannot serve a
     * stale digest or revocation state. The lookup runs inside
     * `WriteConnection::during()` for the device model, so relations the device
     * model eager-loads come from the writer too.
     *
     * An id that cannot be a key of the device model names no device and is
     * rejected without a query; database errors on a well-formed id propagate.
     *
     * @param  mixed  $id
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function findDeviceById(mixed $id): (EloquentDevice&Model)|null
    {
        $class = Config::string('authentication.device.model', '');

        InvalidDeviceModelConfigurationException::validate($class);

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice $model */
        $model = new $class;

        if (!DeviceKeyShape::matches($model, $id)) {
            return null;
        }

        $device = WriteConnection::during($model, static fn (): mixed => WriteConnection::query($model->newQuery())->find($id));

        return $device instanceof Model ? $device : null;
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
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
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
     * Reload the device's owner through the guard's identity provider, so the
     * provider's own scoping applies, and confirm it is that exact owner and
     * currently active. A device row with no owner key, or a provider answer
     * that is not the owner (no row through this provider, or another model
     * sharing the key), fails as `authenticatable_missing`.
     *
     * The provider is asked for the owner key the device row stores, which is
     * the identity's primary key; providers find identities by their auth
     * identifier, which is the primary key unless the identity model overrides
     * `getAuthIdentifierName()`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  ?string  $deviceId
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function resolveRefreshIdentity(EloquentDevice&Model $device, ?string $deviceId): ?Identity
    {
        $ownerKey = DeviceOwnership::ownerKey($device);
        $identity = $ownerKey === null ? null : $this->provider->retrieveById($ownerKey);

        if (!$identity instanceof Identity || !DeviceOwnership::isOwner($device, $identity)) {

            $this->dispatchRefreshFailure(RefreshFailureReason::AUTHENTICATABLE_MISSING, $deviceId);

            return null;
        }

        if (!ActivationPolicy::isActive($identity)) {

            $this->dispatchRefreshFailure(RefreshFailureReason::IDENTITY_INACTIVE, $deviceId);

            return null;
        }

        return $identity;
    }

    /**
     * Resolve a principal for the refresh-flow identity and verify it and the
     * tenant it acts within are currently active.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $deviceId
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveRefreshPrincipal(Identity $identity, ?string $deviceId, mixed $hint = null): ?Principal
    {
        $hintProvided = $hint !== null;
        $principal    = $this->resolvePrincipal($identity, $hint);

        if ($hintProvided && !IdentifierCoercion::matches($principal?->getPrincipalIdentifier(), $hint)) {

            $this->dispatchRefreshFailure(RefreshFailureReason::PRINCIPAL_MISMATCH, $deviceId);

            return null;
        }

        if (!$principal instanceof Principal) {

            $this->dispatchRefreshFailure(RefreshFailureReason::PRINCIPAL_UNRESOLVED, $deviceId);

            return null;
        }

        if (!ActivationPolicy::isActive($principal)) {

            $this->dispatchRefreshFailure(RefreshFailureReason::PRINCIPAL_INACTIVE, $deviceId);

            return null;
        }

        if (!ActivationPolicy::isTenantActive($principal)) {

            $this->dispatchRefreshFailure(RefreshFailureReason::TENANT_INACTIVE, $deviceId);

            return null;
        }

        return $principal;
    }

    /**
     * Resolve a principal for the identity through the bound resolver. An
     * `UnresolvableIdentityException` is a misconfiguration and propagates as a
     * server error rather than being reported as a refresh failure.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolvePrincipal(Identity $identity, mixed $hint = null): ?Principal
    {
        return $hint === null
            ? $this->resolver->resolve($identity)
            : $this->resolver->resolve($identity, $hint);
    }

    /**
     * Issue the new token pair, then atomically rotate the digest and move the
     * idle deadline forward via a compare-and-swap UPDATE, and assemble the
     * DTO. Does NOT bind any state on a guard.
     *
     * The new idle deadline is the idle lifetime from `$now`, never past the
     * absolute deadline, which a rotation never moves. Both tokens are issued
     * at `$now`, the time the device was judged at, before the CAS, so a
     * failure while issuing (signing, randomness, an identifier that cannot be
     * read) propagates before anything is written and the presented refresh
     * token stays valid. The pair is only returned once the CAS has committed.
     *
     * Returns `null` when the CAS affects zero rows: the token verified earlier
     * but a concurrent refresh (or a stolen-token replay) has rotated the
     * digest, or the device's deadlines changed, in between. The issued pair is
     * discarded, the whole device is revoked, and `rotation_reuse` is
     * dispatched.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $oldRotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Carbon\CarbonInterface  $absolute
     * @return ?\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function completeExchange(
        EloquentDevice&Model $device,
        Identity $identity,
        Principal $principal,
        #[\SensitiveParameter] string $oldRotationId,
        CarbonImmutable $now,
        CarbonInterface $absolute,
    ): ?ExchangedRefresh {
        $newRotationId = RefreshTokenHasher::generate();
        $readDeadlines = $this->storedDeadlines($device);
        $idleColumn    = $device->getIdleExpiresAtName();
        $idle          = $device->fromDateTime($this->tokens->lifetimes()->idleDeadline($now, $absolute));

        $device->setAttribute($idleColumn, $idle);

        $tokens = new RefreshResult(
            $this->tokens->issueAccessToken($identity, $principal, $device, $now),
            $this->tokens->issueRefreshToken($device, $newRotationId, $principal, $now),
        );

        $rotated = $this->atomicallyRotateRefreshKey($device, $oldRotationId, $newRotationId, $readDeadlines, $idle);

        if (!$rotated) {

            $deviceId = IdentifierCoercion::stringify($device->getDeviceIdentifier());

            $this->revokeDevice($device);
            $this->dispatchRefreshFailure(RefreshFailureReason::ROTATION_REUSE, $deviceId);

            return null;
        }

        $device->setAttribute($this->refreshKeyColumn($device), RefreshTokenHasher::hash($newRotationId));
        $device->syncOriginalAttributes([$this->refreshKeyColumn($device), $idleColumn]);

        return new ExchangedRefresh($identity, $principal, $device, $tokens);
    }

    /**
     * The device's idle and absolute deadlines exactly as they were loaded,
     * keyed by column, for the compare-and-swap to match by equality.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return array<string, mixed>
     */
    private function storedDeadlines(EloquentDevice&Model $device): array
    {
        $idle     = $device->getIdleExpiresAtName();
        $absolute = $device->getAbsoluteExpiresAtName();

        return [
            $idle     => $device->getRawOriginal($idle),
            $absolute => $device->getRawOriginal($absolute),
        ];
    }

    /**
     * Rotate the device's stored digest and move its idle deadline forward via
     * a single compare-and-swap UPDATE keyed on the device id, the old digest,
     * a null `revoked_at`, and both deadlines exactly as they were read.
     * Returns `true` when exactly one row was affected. `false` signals a
     * concurrent rotation, revocation, or deadline change, and the caller
     * treats it as refresh reuse.
     *
     * Raw query-builder update bypasses Eloquent events; consumer side effects
     * should trigger on the `Refreshed` package event.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $oldRotationId
     * @param  string  $newRotationId
     * @param  array<string, mixed>  $readDeadlines
     * @param  ?string  $idle
     * @return bool
     *
     * @imperative
     */
    private function atomicallyRotateRefreshKey(
        EloquentDevice&Model $device,
        #[\SensitiveParameter] string $oldRotationId,
        #[\SensitiveParameter] string $newRotationId,
        array $readDeadlines,
        ?string $idle,
    ): bool {
        $column     = $this->refreshKeyColumn($device);
        $revokedCol = $this->revokedAtColumn($device);
        $idleColumn = $device->getIdleExpiresAtName();

        $affected = $this->connections
            ->connection($device->getConnectionName())
            ->table($device->getTable())
            ->where($device->getKeyName(), $device->getKey())
            ->where($column, RefreshTokenHasher::hash($oldRotationId))
            ->whereNull($revokedCol)
            ->where($readDeadlines)
            ->update([
                $column     => RefreshTokenHasher::hash($newRotationId),
                $idleColumn => $idle,
            ]);

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
