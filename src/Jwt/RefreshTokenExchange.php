<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * Refresh-token exchange service.
 *
 * The device's owner is reloaded through the guard's identity provider, so the
 * provider's scopes apply and an owner the guard does not serve is rejected. A
 * token is honoured only for a device of the guard exchanging it, and only
 * while the guard's audience policy still lets the method that started the
 * session start one and still admits the owner as the principal; none of these
 * failures revokes the device. The next idle deadline follows the lifetimes the
 * policy gives the principal's type.
 *
 * Failed exchanges are counted against the token's device and the client's IP
 * address; once either count is full the exchange is refused as `rate_limited`
 * before the device is looked up.
 *
 * A validly signed token for a live device carries one of three rotation ids:
 * - the current one: the exchange rotates it to its successor with a
 *   compare-and-swap that also moves the session's idle deadline;
 * - the one the current one replaced, inside the grace window: the exchange
 *   hands back the current credential (a fresh pair whose refresh token carries
 *   the current rotation id) and writes no rotation state, so retries
 *   neither extend the window nor disturb the swap;
 * - any other: the token was rotated before, so it is a replay, and the device
 *   is revoked (`rotation_reuse`). A device that holds no refresh credential
 *   cannot tell a replay from anything else, so its tokens are rejected without
 *   revoking it.
 *
 * Every check uses one time per exchange, taken after the token is parsed and
 * cut to the whole second. Failure paths dispatch `RefreshFailed` events with
 * machine-readable reason codes for SIEM attribution.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RefreshTokenExchange
{
    /** @var \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore Guarded writes and locking reads of the device's refresh state. */
    private readonly RefreshRotationStore $store;

    /** @var \SineMacula\Laravel\Authentication\Database\AfterCommit Defers `DeviceRevoked` until the revocation commits. */
    private readonly AfterCommit $afterCommit;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Closure(): mixed  $transactions
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  string  $guardName
     */
    public function __construct(

        /** Token service for parsing and issuing tokens. */
        private readonly JwtTokenService $tokens,

        /** The guard's identity provider, which reloads the device owner. */
        private readonly IdentityProvider $provider,

        // Connection resolver for the device's refresh state writes.
        ConnectionResolverInterface $connections,

        // Returns the current transactions manager, if any, when called.
        \Closure $transactions,

        /** Event dispatcher for RefreshFailed and DeviceRevoked events. */
        private Dispatcher $events,

        /** Resolver mapping identity to acting principal. */
        private PrincipalResolver $resolver,

        /** Guard name carried on every RefreshFailed and DeviceRevoked event. */
        private readonly string $guardName,
    ) {
        $this->store       = new RefreshRotationStore($connections);
        $this->afterCommit = new AfterCommit($transactions);
    }

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
     * Rebind the event dispatcher that receives `RefreshFailed` and
     * `DeviceRevoked`, so a dispatcher swapped in after the guard resolved
     * (e.g. `Event::fake()`) receives the exchange's events as well as the
     * guard's.
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
     * Exchange a refresh token for a new access + refresh token pair. On any
     * failure, the `RefreshFailed` event is dispatched and returned, and the
     * failure is counted against the token's device and the client's IP
     * address.
     *
     * Refreshing cannot guess a secret, so only failures are counted. Once
     * either count is full the exchange stops before looking the device up and
     * fails as `rate_limited`, carrying the seconds until the full count's
     * window ends; that failure is not counted itself.
     *
     * @param  string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\RefreshFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function exchange(#[\SensitiveParameter] string $refreshToken, ClientContext $client): ExchangedRefresh|RefreshFailed
    {
        $claims  = $this->tokens->parse($refreshToken, TokenType::REFRESH);
        $subject = new AttemptSubject($this->guardName, AttemptFlow::REFRESH, IdentifierCoercion::stringify($claims[Claims::DEVICE_ID->value] ?? null), null, $client->ip);
        $limiter = Container::getInstance()->make(AttemptLimiter::class);
        $wait    = $limiter->blocked($subject);

        $outcome = $wait === null
            ? $this->exchangeClaims($claims)
            : $this->failure(RefreshFailureReason::RATE_LIMITED, $subject->identifier, $wait);

        if ($outcome instanceof RefreshFailed && $wait === null) {
            $limiter->recordFailure($subject);
        }

        if ($outcome instanceof RefreshFailed) {
            $this->events->dispatch($outcome);
        }

        return $outcome;
    }

    /**
     * Revoke a device with the given reason: its tokens stop working at once,
     * on the bearer path and on refresh. Idempotent: an already revoked device
     * keeps its first revocation's time and reason. Returns whether this call
     * revoked the device; when it did, the revocation is mirrored on the
     * in-memory device and `DeviceRevoked` is dispatched once the revocation is
     * committed on the device's connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return bool
     *
     * @imperative
     */
    public function revokeDevice(EloquentDevice&Model $device, RevocationReason $reason): bool
    {
        return $this->revoke($device, $reason, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Run the exchange for the parsed claims: the device the token names, its
     * guard, the rotation id against it, its owner and principal, and the
     * guard's audience policy, then the rotation or the grace reissue. Returns
     * the `RefreshFailed` event of the first check that fails.
     *
     * @param  ?array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Authentication\Events\RefreshFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function exchangeClaims(#[\SensitiveParameter] ?array $claims): ExchangedRefresh|RefreshFailed
    {
        $claims = $this->extractRefreshClaims($claims);

        if ($claims instanceof RefreshFailed) {
            return $claims;
        }

        [$rawDeviceId, $rotationId, $principalHint] = $claims;

        $device = DeviceLookup::find($rawDeviceId);

        return $device === null
            ? $this->failure(RefreshFailureReason::DEVICE_UNKNOWN, IdentifierCoercion::stringify($rawDeviceId))
            : $this->exchangeOn($device, $rotationId, $principalHint, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Run the exchange on the device the token names. A device of another guard
     * (or of none), read on the write connection, fails as
     * `device_guard_mismatch` before anything else is judged, so a token of one
     * guard can never revoke another guard's device. A failure that proves a
     * replay revokes the device; no other one does.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $rotationId
     * @param  mixed  $principalHint
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\RefreshFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function exchangeOn(EloquentDevice&Model $device, #[\SensitiveParameter] string $rotationId, mixed $principalHint, CarbonImmutable $now): ExchangedRefresh|RefreshFailed
    {
        $guard   = WriteConnection::during($device, static fn (): ?string => $device->getGuard());
        $verdict = $guard === $this->guardName
            ? $this->classify($device, $rotationId, $now)
            : RefreshFailureReason::DEVICE_GUARD_MISMATCH;

        if ($verdict instanceof RefreshFailureReason) {
            return $this->fail($device, $verdict, $now);
        }

        $context = $this->hydrateRefreshContext($device, $principalHint);

        if ($context instanceof RefreshFailureReason) {
            return $this->failure($context, IdentifierCoercion::stringify($device->getDeviceIdentifier()));
        }

        [$identity, $principal] = $context;

        return $verdict[0] === RotationMatch::CURRENT
            ? $this->rotate($device, $identity, $principal, $rotationId, $now, $verdict[1])
            : $this->reissue($device, $identity, $principal, $rotationId, $now);
    }

    /**
     * Extract and shape-check the refresh-token claims. `parse()` has already
     * rejected a token missing `did` or `jti`, so what remains is a `jti` that
     * is not a string. Returns the `token_invalid` failure for any malformed
     * payload.
     *
     * @param  ?array<string, mixed>  $claims
     * @return array{0: mixed, 1: string, 2: mixed}|\SineMacula\Laravel\Authentication\Events\RefreshFailed
     */
    private function extractRefreshClaims(#[\SensitiveParameter] ?array $claims): array|RefreshFailed
    {
        if ($claims === null) {
            return $this->failure(RefreshFailureReason::TOKEN_INVALID, null);
        }

        $rawDeviceId   = $claims[Claims::DEVICE_ID->value];
        $rotationId    = $claims[Claims::JWT_ID->value];
        $principalHint = $claims[Claims::PRINCIPAL_ID->value] ?? null;

        if (!is_string($rotationId)) {
            return $this->failure(RefreshFailureReason::TOKEN_INVALID, is_string($rawDeviceId) ? $rawDeviceId : null);
        }

        /** @var non-empty-string $rotationId */
        return [$rawDeviceId, $rotationId, $principalHint];
    }

    /**
     * The `RefreshFailed` event for the reason and device id, and the wait of a
     * rate-limited failure.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason  $reason
     * @param  ?string  $deviceId
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\Events\RefreshFailed
     */
    private function failure(RefreshFailureReason $reason, ?string $deviceId, ?int $retryAfter = null): RefreshFailed
    {
        return new RefreshFailed($this->guardName, $reason, $deviceId, $retryAfter);
    }

    /**
     * The failure of an exchange on the device, first revoking the device when
     * the failure proves its refresh token was replayed.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\RefreshFailed
     */
    private function fail(EloquentDevice&Model $device, RefreshFailureReason $reason, CarbonImmutable $now): RefreshFailed
    {
        if ($reason === RefreshFailureReason::ROTATION_REUSE) {
            $this->revoke($device, RevocationReason::ROTATION_REUSE, $now);
        }

        return $this->failure($reason, IdentifierCoercion::stringify($device->getDeviceIdentifier()));
    }

    /**
     * Revoke the device at the given time, and report it when this call did,
     * once the revocation is committed on the device's own connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @imperative
     */
    private function revoke(EloquentDevice&Model $device, RevocationReason $reason, CarbonImmutable $now): bool
    {
        $revoked = $this->store->revoke($device, $reason, $now);

        if ($revoked) {

            $event = new DeviceRevoked($this->guardName, $device, $reason);

            $this->afterCommit->run($device, function () use ($event): void {
                $this->events->dispatch($event);
            });
        }

        return $revoked;
    }

    /**
     * Judge the presented rotation id against the device at `$now`.
     *
     * In order: a revoked device fails as `device_revoked`; a session past
     * either deadline, or without one, as `session_expired` (an ended session
     * is not revoked: it simply cannot be refreshed); a device holding no
     * refresh credential as `refresh_key_missing`. Only then is the rotation id
     * compared, in constant time: the current one, with the absolute
     * deadline the rotation keeps; the previous one inside the grace window;
     * or anything else, which is a replay (`rotation_reuse`). Nothing is
     * compared before the device is known to be live, so such a row cannot be
     * used to time-probe the valid rotation-id space.
     *
     * The device's state is read inside `WriteConnection::during()` for the
     * device, so a device that derives any of it from a relation or another
     * table reads it from the writer as well.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch, 1: \Carbon\CarbonInterface}|\SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason
     *
     * @formatter:on
     *
     * @throws \LogicException
     */
    private function classify(EloquentDevice&Model $device, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now): array|RefreshFailureReason
    {
        $lifetimes = $this->tokens->lifetimes();

        return WriteConnection::during($device, static function () use ($device, $rotationId, $now, $lifetimes): array|RefreshFailureReason {

            if ($device->getRevokedAt() !== null) {
                return RefreshFailureReason::DEVICE_REVOKED;
            }

            $deadlines = TokenLifetimes::liveDeadlines($device, $now);
            $current   = $device->getRefreshKey();

            if ($deadlines === null || $current === null) {
                return $deadlines === null ? RefreshFailureReason::SESSION_EXPIRED : RefreshFailureReason::REFRESH_KEY_MISSING;
            }

            $match = match (true) {
                RefreshTokenHasher::verify($rotationId, $current)                    => RotationMatch::CURRENT,
                self::isGraceRetry($device, $rotationId, $current, $lifetimes, $now) => RotationMatch::PREVIOUS,
                default                                                              => null,
            };

            return $match === null ? RefreshFailureReason::ROTATION_REUSE : [$match, $deadlines[1]];
        });
    }

    /**
     * Whether the rotation id is the one the device's current id replaced,
     * presented inside the grace window. The current id must also be its
     * successor: a row whose digests were changed outside a rotation does not
     * honour the previous id.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $rotationId
     * @param  string  $current
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isGraceRetry(Device $device, #[\SensitiveParameter] string $rotationId, string $current, TokenLifetimes $lifetimes, CarbonImmutable $now): bool
    {
        $previous  = $device->getPreviousRefreshKey();
        $rotatedAt = $device->getRefreshRotatedAt();

        if ($previous === null || $rotatedAt === null || !$lifetimes->isWithinGrace($rotatedAt, $now)) {
            return false;
        }

        return RefreshTokenHasher::verify($rotationId, $previous)
            && RefreshTokenHasher::verify(RefreshTokenHasher::successor($rotationId), $current);
    }

    /**
     * Hydrate identity + principal from a verified device row, and hold them to
     * the guard's audience policy: the method that started the session must
     * still be allowed to (a device that records none fails closed, as
     * `method_not_allowed`), and the policy must still admit the identity as
     * the principal (`principal_ineligible`). A refresh names no identifier, so
     * the verified-identifier requirement does not apply to it. The method is
     * read inside `WriteConnection::during()`, as the device's state is.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  mixed  $principalHint
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}|\SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function hydrateRefreshContext(EloquentDevice&Model $device, mixed $principalHint): array|RefreshFailureReason
    {
        $identity = $this->resolveRefreshIdentity($device);

        if ($identity instanceof RefreshFailureReason) {
            return $identity;
        }

        $principal = $this->resolveRefreshPrincipal($identity, $principalHint);

        if ($principal instanceof RefreshFailureReason) {
            return $principal;
        }

        $policy  = Container::getInstance()->make(AudiencePolicy::class);
        $method  = WriteConnection::during($device, static fn (): ?string => $device->getSignInMethod());
        $allowed = $method !== null && $policy->allowsMethod($this->guardName, $method);

        return match (true) {
            !$allowed                                                              => RefreshFailureReason::METHOD_NOT_ALLOWED,
            $policy->admit($this->guardName, $identity, $principal, null) !== null => RefreshFailureReason::PRINCIPAL_INELIGIBLE,
            default                                                                => [$identity, $principal],
        };
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
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason
     */
    private function resolveRefreshIdentity(EloquentDevice&Model $device): Identity|RefreshFailureReason
    {
        $ownerKey = DeviceOwnership::ownerKey($device);
        $identity = $ownerKey === null ? null : $this->provider->retrieveById($ownerKey);

        if (!$identity instanceof Identity || !DeviceOwnership::isOwner($device, $identity)) {
            return RefreshFailureReason::AUTHENTICATABLE_MISSING;
        }

        return ActivationPolicy::isActive($identity) ? $identity : RefreshFailureReason::IDENTITY_INACTIVE;
    }

    /**
     * Resolve a principal for the refresh-flow identity through the bound
     * resolver, with the token's hint when it carries one, and verify it and
     * the tenant it acts within are currently active. An
     * `UnresolvableIdentityException` is a misconfiguration and propagates as a
     * server error rather than being reported as a refresh failure.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|\SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveRefreshPrincipal(Identity $identity, mixed $hint): Principal|RefreshFailureReason
    {
        $principal = $hint === null
            ? $this->resolver->resolve($identity)
            : $this->resolver->resolve($identity, $hint);

        if ($hint !== null && !IdentifierCoercion::matches($principal?->getPrincipalIdentifier(), $hint)) {
            return RefreshFailureReason::PRINCIPAL_MISMATCH;
        }

        if (!$principal instanceof Principal) {
            return RefreshFailureReason::PRINCIPAL_UNRESOLVED;
        }

        return match (true) {
            !ActivationPolicy::isActive($principal)       => RefreshFailureReason::PRINCIPAL_INACTIVE,
            !ActivationPolicy::isTenantActive($principal) => RefreshFailureReason::TENANT_INACTIVE,
            default                                       => $principal,
        };
    }

    /**
     * Rotate the presented current rotation id to its successor and issue the
     * pair for it.
     *
     * The new idle deadline is the idle lifetime the audience policy gives the
     * principal's type, from `$now`, never past the absolute deadline, which a
     * rotation never moves. Both tokens are issued at `$now`, the time the
     * device was judged at, before anything is written, so a failure while
     * issuing (signing, randomness, an identifier that cannot be read) leaves
     * the presented refresh token valid. The pair is only returned once the
     * compare-and-swap has committed; when the swap misses, the row changed
     * under the exchange and is judged again.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Carbon\CarbonInterface  $absolute
     * @return \SineMacula\Laravel\Authentication\Events\RefreshFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function rotate(
        EloquentDevice&Model $device,
        Identity $identity,
        Principal $principal,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
        CarbonInterface $absolute,
    ): ExchangedRefresh|RefreshFailed {
        $next = RefreshTokenHasher::successor($rotationId);
        $idle = Container::getInstance()->make(AudiencePolicy::class)->lifetimes($this->guardName, $principal)->idleDeadline($now, $absolute);

        $device->setAttribute($device->getIdleExpiresAtName(), $idle);

        $tokens = new RefreshResult(
            $this->tokens->issueAccessToken($identity, $principal, $device, $now),
            $this->tokens->issueRefreshToken($device, $next, $principal, $now),
        );

        if ($this->store->rotate($device, $rotationId, $next, $idle, $now)) {
            return new ExchangedRefresh($identity, $principal, $device, $tokens);
        }

        return $this->afterLostRotation($device, $identity, $principal, $rotationId, $now);
    }

    /**
     * Judge the presented rotation id again against the row as it now is, after
     * the compare-and-swap missed, with the same `$now`. There is never a
     * second swap.
     *
     * The usual cause is a parallel refresh with the same token that rotated
     * first; its successor is this exchange's, so this one is a grace retry and
     * gets the current credential. A replay is revoked, and a device that was
     * revoked, deleted, or ended in between fails for that reason. A token that
     * is still the current one means other security state changed in between (a
     * deadline, say): that proves nothing, so it fails as `rotation_conflict`
     * without revoking, and the client can retry. Before any success the fresh
     * row must still belong to the identity the exchange hydrated.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\RefreshFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function afterLostRotation(
        EloquentDevice&Model $device,
        Identity $identity,
        Principal $principal,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
    ): ExchangedRefresh|RefreshFailed {
        $fresh = $this->store->reload($device);

        if ($fresh === null) {
            return $this->failure(RefreshFailureReason::DEVICE_UNKNOWN, IdentifierCoercion::stringify($device->getDeviceIdentifier()));
        }

        $verdict = $this->classify($fresh, $rotationId, $now);

        if (is_array($verdict)) {
            $verdict = match (true) {
                $verdict[0] === RotationMatch::CURRENT       => RefreshFailureReason::ROTATION_CONFLICT,
                !DeviceOwnership::isOwner($fresh, $identity) => RefreshFailureReason::AUTHENTICATABLE_MISSING,
                default                                      => null,
            };
        }

        return $verdict === null
            ? $this->reissue($fresh, $identity, $principal, $rotationId, $now)
            : $this->fail($fresh, $verdict, $now);
    }

    /**
     * Hand a grace retry the session's current credential: a new pair, issued
     * at `$now`, whose refresh token carries the current rotation id (the
     * successor of the presented one) and expires at the stored idle deadline.
     * No rotation state is written, so the grace window stays anchored at the
     * rotation that opened it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function reissue(
        EloquentDevice&Model $device,
        Identity $identity,
        Principal $principal,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
    ): ExchangedRefresh {
        $tokens = new RefreshResult(
            $this->tokens->issueAccessToken($identity, $principal, $device, $now),
            $this->tokens->issueRefreshToken($device, RefreshTokenHasher::successor($rotationId), $principal, $now),
        );

        return new ExchangedRefresh($identity, $principal, $device, $tokens);
    }
}
