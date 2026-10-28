<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Guards\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;
use SineMacula\Laravel\Authentication\Jwt\DeviceOwnership;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Jwt\RefreshJudgement;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;

/**
 * Switches a device's session to another principal of the same identity, proven
 * by the device's refresh token (never by an access token: a stolen short-lived
 * access token must not mint a refresh credential).
 *
 * The token is judged as a refresh judges it, counted against the same refresh
 * limits, and a replayed one revokes the device. Every live check runs on every
 * path: the owner, reloaded through the guard's provider and active; the
 * target, resolved through the hinted path as the very principal named, owned,
 * active, in an active tenant, and admitted by the audience policy; the
 * session's sign-in method still allowed; and the additional-factor policy,
 * which may not ask for a further factor (sign in again as the target then).
 *
 * With the current rotation id, the token's principal must be the one the
 * device records. The switch keeps the session's absolute clock, held to the
 * target type's absolute lifetime counted from the sign-in, restarts the idle
 * one, issues both tokens for the target at `$now` before writing, and writes
 * the target, the switch time, the rotation and both deadlines in one
 * compare-and-swap. A switch to the principal the device already records
 * rotates like a refresh. With the previous rotation id inside the grace
 * window, the current credential is handed back only when the device already
 * records the target from that very rotation (a lost switch response retried)
 * or the token's own principal is the target; anything else is a conflict,
 * without revoking. A missed swap re-reads the row with a lock and judges it
 * once more; there is never a second swap.
 *
 * One switch is one instance, built with the guard, the client and the target
 * when the switch runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PrincipalSwitch
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore  $store
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $target
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice, \Carbon\CarbonImmutable): bool  $revoke
     */
    public function __construct(

        /** The guard's token service, which parses the proof and issues the pair. */
        private JwtTokenService $tokens,

        /** The guarded switch write and the locking re-read. */
        private RefreshRotationStore $store,

        /** The guard whose session switches. */
        private JwtGuard $guard,

        /** The client of the request asking for the switch. */
        private ClientContext $client,

        /** The principal to switch to. */
        private Principal $target,

        /** Revokes a device whose refresh token was replayed, and reports it. */
        private \Closure $revoke,
    ) {}

    /**
     * Switch the session the refresh token proves to the target. Returns the
     * switched session, or the `AuthenticationFailed` event that reports why it
     * was refused, undispatched. A failure is counted against the token's
     * device and the client's IP address; once either count is full the switch
     * is refused as `rate_limited` before the device is looked up.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    public function switch(#[\SensitiveParameter] string $refreshToken): AuthenticationFailed|SwitchedPrincipal
    {
        $claims   = $this->tokens->parse($refreshToken, TokenType::REFRESH);
        $deviceId = IdentifierCoercion::stringify($claims[Claims::DEVICE_ID->value] ?? null);
        $subject  = new AttemptSubject($this->guard->getName(), AttemptFlow::REFRESH, $deviceId, null, $this->client->ip);
        $limiter  = Container::getInstance()->make(AttemptLimiter::class);
        $wait     = $limiter->blocked($subject);

        if ($wait !== null) {
            return self::refused(FailureReason::RATE_LIMITED, new EventContext($this->guard->getName(), $this->client, deviceId: $deviceId), $wait);
        }

        $outcome = $this->switchClaims($claims);

        if ($outcome instanceof AuthenticationFailed) {
            $limiter->recordFailure($subject);
        }

        return $outcome;
    }

    /**
     * Run the switch for the parsed claims on the device they name.
     *
     * @param  ?array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function switchClaims(#[\SensitiveParameter] ?array $claims): AuthenticationFailed|SwitchedPrincipal
    {
        $rotationId = $claims[Claims::JWT_ID->value] ?? null;

        if ($claims === null || !is_string($rotationId)) {
            return self::refused(FailureReason::TOKEN_INVALID, new EventContext($this->guard->getName(), $this->client));
        }

        $deviceId = $claims[Claims::DEVICE_ID->value];
        $device   = DeviceLookup::find($deviceId);

        return $device === null
            ? self::refused(FailureReason::DEVICE_UNKNOWN, new EventContext($this->guard->getName(), $this->client, deviceId: IdentifierCoercion::stringify($deviceId)))
            : $this->switchOn($device, [$rotationId, $claims[Claims::PRINCIPAL_ID->value] ?? null]);
    }

    /**
     * Run the switch on the device the token names: its guard, the rotation id
     * against it, the target's admission, then the switch or the retry.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  array{0: string, 1: mixed}  $presented
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function switchOn(EloquentDevice&Model $device, #[\SensitiveParameter] array $presented): AuthenticationFailed|SwitchedPrincipal
    {
        $now     = CarbonImmutable::now()->startOfSecond();
        $verdict = WriteConnection::during($device, static fn (): ?string => $device->getGuard()) === $this->guard->getName()
            ? RefreshJudgement::classify($device, $presented[0], $now, $this->tokens->lifetimes())
            : FailureReason::DEVICE_GUARD_MISMATCH;

        if ($verdict instanceof FailureReason) {
            return $this->fail($device, $verdict, $now);
        }

        $admitted = $this->admit($device);

        return match (true) {
            $admitted instanceof AuthenticationFailed => $admitted,
            $verdict[0] === RotationMatch::CURRENT    => $this->switchCurrent($device, $admitted, $presented, $now),
            default                                   => $this->retry($device, $admitted, $presented),
        };
    }

    /**
     * Admit the target for the device's session: the device's owner, active, as
     * the target resolved through the hinted path (the very principal named,
     * owned, active, in an active tenant, admitted by the audience policy),
     * with the session's sign-in method still allowed and no further factor
     * asked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn
     *
     * @throws \Throwable
     */
    private function admit(EloquentDevice&Model $device): AdmittedSignIn|AuthenticationFailed
    {
        $admitted = (new RefreshAdmission($this->guard->getName(), $this->guard->getProvider(), $this->guard->getPrincipalResolver()))
            ->admit($device, $this->target->getPrincipalIdentifier() ?? '');

        if ($admitted instanceof AdmittedSignIn && !$this->isTarget($admitted)) {
            $admitted = new RefusedSignIn(FailureReason::PRINCIPAL_MISMATCH, $admitted->identity);
        }

        if ($admitted instanceof AdmittedSignIn && $this->requiresAdditionalFactor($admitted, $device)) {
            $admitted = RefusedSignIn::after(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $admitted);
        }

        return $admitted instanceof RefusedSignIn
            ? self::refused($admitted->reason, $this->context($device, $admitted))
            : $admitted;
    }

    /**
     * Whether the principal the hinted path resolved (whose identifier the
     * admission already matched to the target's) is the very target: of its
     * class, and owned by the device's owner, read from the principal's own
     * stored key rather than trusted to the resolver.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @return bool
     */
    private function isTarget(AdmittedSignIn $admitted): bool
    {
        return $admitted->principal::class === $this->target::class
            && PinnedPrincipal::isOwnedBy($admitted->principal, $admitted->identity);
    }

    /**
     * Whether the additional-factor policy asks a further factor of the target
     * on the device.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function requiresAdditionalFactor(AdmittedSignIn $admitted, EloquentDevice&Model $device): bool
    {
        return Container::getInstance()->make(AdditionalFactorPolicy::class)->requiresAdditionalFactor(new AdditionalFactorContext(
            $this->guard->getName(),
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            (string) $device->getSignInMethod(),
            $this->client,
            null,
            null,
            $device,
        ));
    }

    /**
     * Switch the device presenting its current rotation id: the token's
     * principal must be the one the device records, and the session must still
     * be live under the target type's lifetimes.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function switchCurrent(
        EloquentDevice&Model $device,
        AdmittedSignIn $admitted,
        #[\SensitiveParameter] array $presented,
        CarbonImmutable $now,
    ): AuthenticationFailed|SwitchedPrincipal {
        [, $id]    = PrincipalReference::columns($device);
        $deadlines = $this->deadlines($device, $admitted->principal, $now);

        $refusal = match (true) {
            !IdentifierCoercion::matches($device->getRawOriginal($id), $presented[1]) => FailureReason::DEVICE_PRINCIPAL_MISMATCH,
            $deadlines[1]->getTimestamp() <= $now->getTimestamp()                     => FailureReason::SESSION_EXPIRED,
            default                                                                   => null,
        };

        return $refusal === null
            ? $this->rotateTo($device, $admitted, $presented, $deadlines, $now)
            : self::refused($refusal, $this->context($device, $admitted));
    }

    /**
     * Issue the pair for the target before the one compare-and-swap that
     * records the switch, the rotation and the deadlines.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @param  array{0: \Carbon\CarbonImmutable, 1: \Carbon\CarbonImmutable}  $deadlines
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function rotateTo(
        EloquentDevice&Model $device,
        AdmittedSignIn $admitted,
        #[\SensitiveParameter] array $presented,
        array $deadlines,
        CarbonImmutable $now,
    ): AuthenticationFailed|SwitchedPrincipal {
        [$type, $id] = PrincipalReference::columns($device);
        $previous    = [IdentifierCoercion::stringify($device->getRawOriginal($type)), IdentifierCoercion::stringify($device->getRawOriginal($id))];
        $switching   = !PrincipalReference::isRecordedOn($device, $admitted->principal);
        $next        = RefreshTokenHasher::successor($presented[0]);

        // Both tokens end with the session, now at its restarted idle deadline,
        // which is never after the absolute one.
        $device->setAttribute($device->getIdleExpiresAtName(), $deadlines[0]);

        $tokens = $this->issue($admitted, $device, $next, $now);

        if (!$this->store->switchPrincipal($device, $presented[0], $next, $admitted->principal, $switching, $deadlines, $now)) {
            return $this->afterLostSwitch($device, $admitted, $presented, $now);
        }

        return new SwitchedPrincipal(self::exchanged($admitted, $device, $tokens), $previous[0], $previous[1], $switching);
    }

    /**
     * Answer a switch presenting the rotation id the device's current one
     * replaced, inside the grace window: hand back the current credential for
     * the target, writing nothing, only when the device records the target and
     * either its last rotation was a switch (a lost switch response retried) or
     * the token's own principal is the target; anything else is a conflict the
     * client can retry, not a replay.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function retry(EloquentDevice&Model $device, AdmittedSignIn $admitted, #[\SensitiveParameter] array $presented): AuthenticationFailed|SwitchedPrincipal
    {
        $honoured = PrincipalReference::isRecordedOn($device, $admitted->principal)
            && (self::isLastRotationASwitch($device) || IdentifierCoercion::matches($admitted->principal->getPrincipalIdentifier(), $presented[1]));

        if (!$honoured) {
            return self::refused(FailureReason::ROTATION_CONFLICT, $this->context($device, $admitted));
        }

        $now    = CarbonImmutable::now()->startOfSecond();
        $tokens = $this->issue($admitted, $device, RefreshTokenHasher::successor($presented[0]), $now);
        $type   = PrincipalReference::type($admitted->principal);
        $id     = PrincipalReference::id($admitted->principal);

        return new SwitchedPrincipal(self::exchanged($admitted, $device, $tokens), $type, $id, false);
    }

    /**
     * Judge the presented rotation id again against the row as it now is, after
     * the compare-and-swap missed, read with a lock: a retry is answered as
     * `retry()` answers it, a still-current id is a conflict, and anything else
     * fails for its reason. There is never a second swap.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function afterLostSwitch(
        EloquentDevice&Model $device,
        AdmittedSignIn $admitted,
        #[\SensitiveParameter] array $presented,
        CarbonImmutable $now,
    ): AuthenticationFailed|SwitchedPrincipal {
        $fresh = $this->store->reload($device);

        if ($fresh === null) {
            return self::refused(FailureReason::DEVICE_UNKNOWN, new EventContext(
                $this->guard->getName(),
                $this->client,
                deviceId: IdentifierCoercion::stringify($device->getDeviceIdentifier()),
            ));
        }

        $verdict = RefreshJudgement::classify($fresh, $presented[0], $now, $this->tokens->lifetimes());

        $refusal = match (true) {
            $verdict instanceof FailureReason                      => $verdict,
            $verdict[0] === RotationMatch::CURRENT                 => FailureReason::ROTATION_CONFLICT,
            !DeviceOwnership::isOwner($fresh, $admitted->identity) => FailureReason::IDENTITY_UNKNOWN,
            default                                                => null,
        };

        return $refusal === null
            ? $this->retry($fresh, $admitted->on($fresh), $presented)
            : self::refused($refusal, $this->context($fresh, $admitted));
    }

    /**
     * The session's deadlines under the target, idle then absolute: the
     * absolute one kept, held to the target type's absolute lifetime counted
     * from the sign-in, and the idle one restarted from `$now` within it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $target
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \Carbon\CarbonImmutable, 1: \Carbon\CarbonImmutable}
     *
     * @throws \Throwable
     */
    private function deadlines(EloquentDevice&Model $device, Principal $target, CarbonImmutable $now): array
    {
        $lifetimes = Container::getInstance()->make(AudiencePolicy::class)->lifetimes($this->guard->getName(), $target);
        $stored    = CarbonImmutable::instance($device->getAbsoluteExpiresAt() ?? $now);
        $signedIn  = $device->getSignedInAt();
        $absolute  = $signedIn === null ? $stored : $stored->min($lifetimes->absoluteDeadline($signedIn));

        return [$lifetimes->idleDeadline($now, $absolute), $absolute];
    }

    /**
     * Issue the pair for the admitted target on the device at `$now`, the
     * refresh token carrying the rotation id.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function issue(AdmittedSignIn $admitted, EloquentDevice&Model $device, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now): RefreshResult
    {
        return new RefreshResult(
            $this->tokens->issueAccessToken($admitted->identity, $admitted->principal, $device, $now),
            $this->tokens->issueRefreshToken($device, $rotationId, $admitted->principal, $now),
        );
    }

    /**
     * The failure of a switch on the device, first revoking the device when the
     * failure proves its refresh token was replayed.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function fail(EloquentDevice&Model $device, FailureReason $reason, CarbonImmutable $now): AuthenticationFailed
    {
        if ($reason === FailureReason::ROTATION_REUSE) {
            ($this->revoke)($device, $now);
        }

        return self::refused($reason, $this->context($device));
    }

    /**
     * The context of a switch on the device: the guard, the client, the device
     * and the method its session records, and whatever of the identity,
     * principal and tenant the switch resolved. A failure before the owner was
     * read (the row's own state, an owner that no longer loads) is about the
     * row, so it names the owner and principal the row records; a refusal of
     * the target names the principal resolved for it, if any, never the one the
     * device acts as.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn|null  $outcome
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function context(EloquentDevice&Model $device, AdmittedSignIn|RefusedSignIn|null $outcome = null): EventContext
    {
        return new EventContext(
            $this->guard->getName(),
            $this->client,
            $outcome?->identity,
            $outcome?->principal,
            $outcome?->tenant,
            $device,
            $device->getSignInMethod(),
            fromDevice: $outcome?->identity === null,
        );
    }

    /**
     * Whether the device's last rotation was a switch of principal: the switch
     * and the rotation were recorded at the same second.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isLastRotationASwitch(EloquentDevice&Model $device): bool
    {
        $switchedAt = $device->getPrincipalSwitchedAt();

        return $switchedAt !== null && $switchedAt->getTimestamp() === $device->getRefreshRotatedAt()?->getTimestamp();
    }

    /**
     * The exchanged session on the device, as the admitted target, with its new
     * pair.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshResult  $tokens
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     */
    private static function exchanged(AdmittedSignIn $admitted, EloquentDevice&Model $device, RefreshResult $tokens): ExchangedRefresh
    {
        return new ExchangedRefresh($admitted->identity, $admitted->principal, $device, $tokens, $admitted->tenant, $device->getSignInMethod());
    }

    /**
     * The `AuthenticationFailed` event of a switch refused for the reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private static function refused(FailureReason $reason, EventContext $context, ?int $retryAfter = null): AuthenticationFailed
    {
        return new AuthenticationFailed($context, AuthenticationFlow::PRINCIPAL_SWITCH, $reason, retryAfter: $retryAfter);
    }
}
