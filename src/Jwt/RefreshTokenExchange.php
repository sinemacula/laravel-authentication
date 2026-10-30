<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Devices\DeviceLookup;
use SineMacula\Laravel\Authentication\Devices\DeviceOwnership;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Refresh-token exchange service.
 *
 * The device's owner is reloaded through the guard's identity provider, so the
 * provider's scopes apply and an owner the guard does not serve is rejected. A
 * token is honoured only for a device of the guard exchanging it, and only
 * while the guard's audience policy still lets the method that started the
 * session start one and still admits the owner as the principal; none of these
 * failures revokes the device. The principal the token names must be the one
 * the device records: after the session switched principal, the refresh tokens
 * of the principal it left fail as `device_principal_mismatch`, without
 * revoking the device. The next idle deadline follows the lifetimes the policy
 * gives the principal's type.
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
 * cut to the whole second. A failure is returned as the `AuthenticationFailed`
 * event that reports it, with a machine-readable reason and as much context as
 * the exchange established, for the caller to dispatch.
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

        /** Event dispatcher for DeviceRevoked events. */
        private Dispatcher $events,

        /** Resolver mapping identity to acting principal. */
        private PrincipalResolver $resolver,

        /** Name of the guard whose refresh tokens the exchange accepts. */
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
     * Rebind the event dispatcher that receives `DeviceRevoked`, so a
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
     * Exchange a refresh token for a new access + refresh token pair. On any
     * failure the `AuthenticationFailed` event that reports it is returned, not
     * dispatched, and the failure is counted against the token's device and the
     * client's IP address.
     *
     * Refreshing cannot guess a secret, so only failures are counted. Once
     * either count is full the exchange stops before looking the device up and
     * fails as `rate_limited`, carrying the seconds until the full count's
     * window ends; that failure is not counted itself.
     *
     * @param  string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function exchange(#[\SensitiveParameter] string $refreshToken, ClientContext $client): AuthenticationFailed|ExchangedRefresh
    {
        $claims  = $this->tokens->parse($refreshToken, TokenType::REFRESH);
        $subject = new AttemptSubject($this->guardName, AttemptFlow::REFRESH, IdentifierCoercion::stringify($claims[Claims::DEVICE_ID->value] ?? null), null, $client->ip);
        $limiter = Container::getInstance()->make(AttemptLimiter::class);
        $wait    = $limiter->blocked($subject);

        $outcome = $wait === null
            ? $this->exchangeClaims($claims, $client)
            : $this->refused(FailureReason::RATE_LIMITED, new EventContext($this->guardName, $client, deviceId: $subject->identifier), $wait);

        if ($outcome instanceof AuthenticationFailed && $wait === null) {
            $limiter->recordFailure($subject);
        }

        return $outcome;
    }

    /**
     * Revoke a device with the given reason: its tokens stop working at once,
     * on the bearer path and on refresh. Idempotent: an already revoked device
     * keeps its first revocation's time and reason. Returns whether this call
     * revoked the device; when it did, the revocation is mirrored on the
     * in-memory device and `DeviceRevoked`, carrying the client, is dispatched
     * once the revocation is committed on the device's connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     *
     * @imperative
     */
    public function revokeDevice(EloquentDevice&Model $device, RevocationReason $reason, ClientContext $client): bool
    {
        return $this->revoke($device, $reason, CarbonImmutable::now()->startOfSecond(), $client);
    }

    /**
     * Run the exchange for the parsed claims: the device the token names, its
     * guard, the rotation id against it, its owner and principal, and the
     * guard's audience policy, then the rotation or the grace reissue. Returns
     * the `AuthenticationFailed` event of the first check that fails.
     *
     * @param  ?array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function exchangeClaims(#[\SensitiveParameter] ?array $claims, ClientContext $client): AuthenticationFailed|ExchangedRefresh
    {
        $claims = $this->extractRefreshClaims($claims, $client);

        if ($claims instanceof AuthenticationFailed) {
            return $claims;
        }

        [$rawDeviceId, $rotationId, $principalHint] = $claims;

        $device = DeviceLookup::find($rawDeviceId);

        return $device === null
            ? $this->refused(FailureReason::DEVICE_UNKNOWN, new EventContext($this->guardName, $client, deviceId: IdentifierCoercion::stringify($rawDeviceId)))
            : $this->exchangeOn($device, $rotationId, $principalHint, CarbonImmutable::now()->startOfSecond(), $client);
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
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function exchangeOn(
        EloquentDevice&Model $device,
        #[\SensitiveParameter] string $rotationId,
        mixed $principalHint,
        CarbonImmutable $now,
        ClientContext $client,
    ): AuthenticationFailed|ExchangedRefresh {
        $guard   = WriteConnection::during($device, static fn (): ?string => $device->getGuard());
        $verdict = $guard === $this->guardName
            ? RefreshJudgement::classify($device, $rotationId, $now, $this->tokens->lifetimes())
            : FailureReason::DEVICE_GUARD_MISMATCH;

        if ($verdict instanceof FailureReason) {
            return $this->fail($device, $verdict, $now, $client);
        }

        $session = $this->hydrateRefreshContext($device, $principalHint, $client);

        if ($session instanceof AuthenticationFailed) {
            return $session;
        }

        return $verdict[0] === RotationMatch::CURRENT
            ? $this->rotate($device, $session, $rotationId, $now, $verdict[1], $client)
            : $this->reissue($device, $session, $rotationId, $now);
    }

    /**
     * Extract and shape-check the refresh-token claims. `parse()` has already
     * rejected a token missing `did` or `jti`, so what remains is a `jti` that
     * is not a string. Returns the `token_invalid` failure for any malformed
     * payload.
     *
     * @param  ?array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return array{0: mixed, 1: string, 2: mixed}|\SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function extractRefreshClaims(#[\SensitiveParameter] ?array $claims, ClientContext $client): array|AuthenticationFailed
    {
        if ($claims === null) {
            return $this->refused(FailureReason::TOKEN_INVALID, new EventContext($this->guardName, $client));
        }

        $rawDeviceId   = $claims[Claims::DEVICE_ID->value];
        $rotationId    = $claims[Claims::JWT_ID->value];
        $principalHint = $claims[Claims::PRINCIPAL_ID->value] ?? null;

        if (!is_string($rotationId)) {
            return $this->refused(FailureReason::TOKEN_INVALID, new EventContext($this->guardName, $client, deviceId: is_string($rawDeviceId) ? $rawDeviceId : null));
        }

        /** @var non-empty-string $rotationId */
        return [$rawDeviceId, $rotationId, $principalHint];
    }

    /**
     * The `AuthenticationFailed` event of a refresh that failed for the reason,
     * with the context the exchange established, and the wait of a rate-limited
     * failure.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function refused(FailureReason $reason, EventContext $context, ?int $retryAfter = null): AuthenticationFailed
    {
        return new AuthenticationFailed($context, AuthenticationFlow::REFRESH, $reason, retryAfter: $retryAfter);
    }

    /**
     * The context of an exchange on the device: the guard exchanging, the
     * client, the device and the method its session records, and whatever of
     * the session's identity, principal and tenant the exchange resolved. A
     * failure before the owner was read (the row's own state, an owner that no
     * longer loads) is about the row, so it names the owner and principal the
     * row records.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function deviceContext(
        ClientContext $client,
        EloquentDevice&Model $device,
        ?Identity $identity = null,
        ?Principal $principal = null,
        ?Tenant $tenant = null,
    ): EventContext {
        return new EventContext($this->guardName, $client, $identity, $principal, $tenant, $device, $device->getSignInMethod(), fromDevice: $identity === null);
    }

    /**
     * The failure of an exchange on the device, first revoking the device when
     * the failure proves its refresh token was replayed.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function fail(EloquentDevice&Model $device, FailureReason $reason, CarbonImmutable $now, ClientContext $client): AuthenticationFailed
    {
        if ($reason === FailureReason::ROTATION_REUSE) {
            $this->revoke($device, RevocationReason::ROTATION_REUSE, $now, $client);
        }

        return $this->refused($reason, $this->deviceContext($client, $device));
    }

    /**
     * Revoke the device at the given time, and report it when this call did,
     * once the revocation is committed on the device's own connection. The
     * event's guard is the device's own.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     *
     * @imperative
     */
    private function revoke(EloquentDevice&Model $device, RevocationReason $reason, CarbonImmutable $now, ClientContext $client): bool
    {
        $revoked = $this->store->revoke($device, $reason, $now);

        if ($revoked) {

            $event = new DeviceRevoked(new EventContext($device->getGuard(), $client, device: $device, method: $device->getSignInMethod(), fromDevice: true), $reason);

            $this->afterCommit->run($device, function () use ($event): void {
                $this->events->dispatch($event);
            });
        }

        return $revoked;
    }

    /**
     * Hydrate identity + principal from a verified device row, and hold them to
     * the guard's audience policy (see `RefreshAdmission`); the principal must
     * be the one the device records (`device_principal_mismatch`). Returns the
     * admitted session (the identity, the principal, the tenant its activity
     * check loaded, and the device), or the failure with as much of it as was
     * resolved.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  mixed  $principalHint
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function hydrateRefreshContext(EloquentDevice&Model $device, mixed $principalHint, ClientContext $client): Admitted|AuthenticationFailed
    {
        $admitted = (new RefreshAdmission($this->guardName, $this->provider, $this->resolver))->admit($device, $principalHint);

        if ($admitted instanceof Admitted && !PrincipalReference::isRecordedOn($device, $admitted->principal)) {
            $admitted = Refused::after(FailureReason::DEVICE_PRINCIPAL_MISMATCH, $admitted);
        }

        return $admitted instanceof Refused
            ? $this->refused($admitted->reason, $this->deviceContext($client, $device, $admitted->identity, $admitted->principal, $admitted->tenant))
            : $admitted;
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
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Carbon\CarbonInterface  $absolute
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function rotate(
        EloquentDevice&Model $device,
        Admitted $session,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
        CarbonInterface $absolute,
        ClientContext $client,
    ): AuthenticationFailed|ExchangedRefresh {
        $next = RefreshTokenHasher::successor($rotationId);
        $idle = Container::getInstance()->make(AudiencePolicy::class)->lifetimes($this->guardName, $session->principal)->idleDeadline($now, $absolute);

        $device->setAttribute($device->getIdleExpiresAtName(), $idle);

        $tokens = new RefreshResult(
            $this->tokens->issueAccessToken($session->identity, $session->principal, $device, $now),
            $this->tokens->issueRefreshToken($device, $next, $session->principal, $now),
        );

        if ($this->store->rotate($device, $rotationId, $next, $idle, $now)) {
            return self::exchanged($device, $session, $tokens);
        }

        return $this->afterLostRotation($device, $session, $rotationId, $now, $client);
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
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function afterLostRotation(
        EloquentDevice&Model $device,
        Admitted $session,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
        ClientContext $client,
    ): AuthenticationFailed|ExchangedRefresh {
        $fresh = $this->store->reload($device);

        if ($fresh === null) {

            $context = new EventContext($this->guardName, $client, deviceId: IdentifierCoercion::stringify($device->getDeviceIdentifier()));

            return $this->refused(FailureReason::DEVICE_UNKNOWN, $context);
        }

        $verdict = RefreshJudgement::classify($fresh, $rotationId, $now, $this->tokens->lifetimes());

        if (is_array($verdict)) {
            $verdict = match (true) {
                $verdict[0] === RotationMatch::CURRENT                         => FailureReason::ROTATION_CONFLICT,
                !DeviceOwnership::isOwner($fresh, $session->identity)          => FailureReason::IDENTITY_UNKNOWN,
                !PrincipalReference::isRecordedOn($fresh, $session->principal) => FailureReason::DEVICE_PRINCIPAL_MISMATCH,
                default                                                        => null,
            };
        }

        return $verdict === null
            ? $this->reissue($fresh, $session, $rotationId, $now)
            : $this->fail($fresh, $verdict, $now, $client);
    }

    /**
     * Hand a grace retry the session's current credential: a new pair, issued
     * at `$now`, whose refresh token carries the current rotation id (the
     * successor of the presented one) and expires at the stored idle deadline.
     * No rotation state is written, so the grace window stays anchored at the
     * rotation that opened it.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function reissue(EloquentDevice&Model $device, Admitted $session, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now): ExchangedRefresh
    {
        $tokens = new RefreshResult(
            $this->tokens->issueAccessToken($session->identity, $session->principal, $device, $now),
            $this->tokens->issueRefreshToken($device, RefreshTokenHasher::successor($rotationId), $session->principal, $now),
        );

        return self::exchanged($device, $session, $tokens);
    }

    /**
     * The exchanged session on the device, with its new pair: the identity,
     * principal and tenant it was admitted as, and the method the device's
     * session records.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshResult  $tokens
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     */
    private static function exchanged(EloquentDevice&Model $device, Admitted $session, RefreshResult $tokens): ExchangedRefresh
    {
        return new ExchangedRefresh($session->identity, $session->principal, $device, $tokens, $session->tenant, $device->getSignInMethod());
    }
}
