<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\ApplicationAdmission;
use SineMacula\Laravel\Authentication\Admission\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Jwt\RefreshJudgment;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Switches a session to another principal of the same identity, proven by the
 * session's refresh token (never by an access token: a stolen short-lived
 * access token must not mint a refresh credential).
 *
 * The token is judged as a refresh judges it, counted against the same refresh
 * limits, and a replayed one revokes the session. Every live check runs on
 * every path: the owner, reloaded through the guard's provider and active; the
 * target, resolved through the hinted path as the very principal named, owned,
 * active, in an active tenant, and admitted by the application policy, also
 * with the type of identifier the session's sign-in used; the session's sign-in
 * method still allowed; and the additional-factor policy, which may not ask for
 * a further factor (sign in again as the target then).
 *
 * A switch keeps the session's absolute clock (it only ever lowers the absolute
 * deadline, to the guard's absolute lifetime from the sign-in, and never adds
 * or extends one), restarts the idle one, and writes in one compare-and-swap.
 *
 * One switch is one instance, built with the guard's context, the client and
 * the target when the switch runs.
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
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $target
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonImmutable): bool  $revoke
     */
    public function __construct(

        /** The guard's token service, which parses the proof and issues the pair. */
        private JwtTokenService $tokens,

        /** The guarded switch write and the locking re-read. */
        private RefreshRotationStore $store,

        /** The context of the guard whose session switches. */
        private GuardContext $context,

        /** The client of the request asking for the switch. */
        private ClientContext $client,

        /** The principal to switch to. */
        private Principal $target,

        /** Revokes a session whose refresh token was replayed, and reports it. */
        private \Closure $revoke,
    ) {}

    /**
     * Switch the session the refresh token proves to the target. Returns the
     * switched session, or the `AuthenticationFailed` event that reports why it
     * was refused, undispatched. A failure is counted against the token's
     * session and the client's IP address; once either count is full the switch
     * is refused as `rate_limited` before the session is looked up.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    public function switch(#[\SensitiveParameter] string $refreshToken): AuthenticationFailed|SwitchedPrincipal
    {
        $claims    = $this->tokens->parse($refreshToken, TokenType::REFRESH);
        $sessionId = IdentifierCoercion::stringify($claims[Claims::SESSION_ID->value] ?? null);
        $subject   = new AttemptSubject($this->context->name(), AttemptFlow::REFRESH, $sessionId, null, $this->client->ip);
        $limiter   = Container::getInstance()->make(AttemptLimiter::class);
        $wait      = $limiter->blocked($subject);

        if ($wait !== null) {
            return self::refused(FailureReason::RATE_LIMITED, new EventContext($this->context->name(), $this->client, sessionId: $sessionId), $wait);
        }

        $outcome = $this->switchClaims($claims);

        if ($outcome instanceof AuthenticationFailed) {
            $limiter->recordFailure($subject);
        }

        return $outcome;
    }

    /**
     * Run the switch for the parsed claims on the session they name.
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
            return self::refused(FailureReason::TOKEN_INVALID, new EventContext($this->context->name(), $this->client));
        }

        $sessionId = $claims[Claims::SESSION_ID->value];
        $session   = SessionLookup::find($sessionId);

        return $session === null
            ? self::refused(FailureReason::SESSION_UNKNOWN, new EventContext($this->context->name(), $this->client, sessionId: IdentifierCoercion::stringify($sessionId)))
            : $this->switchOn($session, [$rotationId, $claims[Claims::PRINCIPAL->value] ?? null]);
    }

    /**
     * Run the switch on the session the token names: its guard, the rotation id
     * against it, the target's admission, then the switch or the retry.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  array{0: string, 1: mixed}  $presented
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function switchOn(EloquentSession&Model $session, #[\SensitiveParameter] array $presented): AuthenticationFailed|SwitchedPrincipal
    {
        $now     = CarbonImmutable::now()->startOfSecond();
        $verdict = WriteConnection::during($session, static fn (): ?string => $session->getGuard()) === $this->context->name()
            ? RefreshJudgment::classify($session, $presented[0], $now, $this->tokens->lifetimes())
            : FailureReason::SESSION_GUARD_MISMATCH;

        if ($verdict instanceof FailureReason) {
            return $this->fail($session, $verdict, $now);
        }

        $admitted = $this->admit($session);

        return match (true) {
            $admitted instanceof AuthenticationFailed => $admitted,
            $verdict[0] === RotationMatch::CURRENT    => $this->switchCurrent($session, $admitted, $presented, $now),
            default                                   => $this->retry($session, $admitted, $presented),
        };
    }

    /**
     * Admit the target for the session: the session's owner, active, as the
     * target resolved through the hinted path (the very principal named, owned,
     * active, in an active tenant, admitted by the application policy), with
     * the session's sign-in method still allowed, then as the target the
     * session's sign-in could have chosen, with no further factor asked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     *
     * @throws \Throwable
     */
    private function admit(EloquentSession&Model $session): Admitted|AuthenticationFailed
    {
        $admitted = (new RefreshAdmission($this->context->name(), $this->context->provider(), $this->context->resolver()))
            ->admit($session, $this->target->getPrincipalIdentifier() ?? '');

        if ($admitted instanceof Admitted) {
            $admitted = $this->admitAsTarget($admitted, $session);
        }

        return $admitted instanceof Refused
            ? self::refused($admitted->reason, $this->eventContext($session, $admitted))
            : $admitted;
    }

    /**
     * Hold the admitted principal to what makes it the target the session may
     * switch to: it must be the very target (`principal_mismatch`); the
     * application policy must admit the identity and then the target with the
     * type of identifier the session's sign-in used, as that sign-in was
     * admitted, so a policy that refuses such an identifier (an unverified one,
     * say), or some principals to it, refuses the switch for its reason; and
     * the additional-factor policy must not ask a further factor
     * (`additional_factor_required`). A session whose sign-in used no
     * identifier is not held to an identifier type. The type is read on the
     * write connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Throwable
     */
    private function admitAsTarget(Admitted $admitted, EloquentSession&Model $session): Admitted|Refused
    {
        if (!$this->isTarget($admitted)) {
            return new Refused(FailureReason::PRINCIPAL_MISMATCH, $admitted->identity);
        }

        $type    = WriteConnection::during($session, static fn (): ?string => $session->getSignInIdentifierType());
        $refusal = $type === null ? null : $this->admitWithType($admitted, $type);

        $refusal ??= $this->requiresAdditionalFactor($admitted, $session) ? FailureReason::ADDITIONAL_FACTOR_REQUIRED : null;

        return $refusal === null ? $admitted : Refused::after($refusal, $admitted);
    }

    /**
     * The application policy's reason to refuse the target to the session's
     * identifier type, if any: first for the identity as a whole, as its
     * sign-in was asked, then for the target.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $type
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function admitWithType(Admitted $admitted, string $type): ?FailureReason
    {
        $policy = Container::getInstance()->make(ApplicationPolicy::class);
        $guard  = $this->context->name();

        return ApplicationAdmission::admitIdentifier($policy, $guard, $admitted->identity, $type)
            ?? ApplicationAdmission::admit($policy, $guard, $admitted->identity, $admitted->principal, $type);
    }

    /**
     * Whether the principal the hinted path resolved (whose identifier the
     * admission already matched to the target's) is the very target: of its
     * class, and owned by the session's owner, read from the principal's own
     * stored key rather than trusted to the resolver.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @return bool
     */
    private function isTarget(Admitted $admitted): bool
    {
        return $admitted->principal::class === $this->target::class
            && PinnedPrincipal::isOwnedBy($admitted->principal, $admitted->identity);
    }

    /**
     * Whether the additional-factor policy asks a further factor of the target
     * on the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function requiresAdditionalFactor(Admitted $admitted, EloquentSession&Model $session): bool
    {
        return Container::getInstance()->make(AdditionalFactorPolicy::class)->requiresAdditionalFactor(new AdditionalFactorContext(
            $this->context->name(),
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            (string) $session->getSignInMethod(),
            $this->client,
            null,
            null,
            $session,
        ));
    }

    /**
     * Switch the session presenting its current rotation id: the token's
     * principal must be the one the session records, and the session must still
     * be live under the guard's lifetimes.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function switchCurrent(
        EloquentSession&Model $session,
        Admitted $admitted,
        #[\SensitiveParameter] array $presented,
        CarbonImmutable $now,
    ): AuthenticationFailed|SwitchedPrincipal {
        [, $id]    = PrincipalReference::columns($session);
        $deadlines = $this->deadlines($session, $now);

        $refusal = match (true) {
            !IdentifierCoercion::matches($session->getRawOriginal($id), $presented[1])      => FailureReason::SESSION_PRINCIPAL_MISMATCH,
            $deadlines[1] !== null && $deadlines[1]->getTimestamp() <= $now->getTimestamp() => FailureReason::SESSION_EXPIRED,
            default                                                                         => null,
        };

        return $refusal === null
            ? $this->rotateTo($session, $admitted, $presented, $deadlines, $now)
            : self::refused($refusal, $this->eventContext($session, $admitted));
    }

    /**
     * Issue the pair for the target before the one compare-and-swap that
     * records the switch, the rotation and the deadlines.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @param  array{0: \Carbon\CarbonImmutable, 1: ?\Carbon\CarbonImmutable}  $deadlines
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function rotateTo(
        EloquentSession&Model $session,
        Admitted $admitted,
        #[\SensitiveParameter] array $presented,
        array $deadlines,
        CarbonImmutable $now,
    ): AuthenticationFailed|SwitchedPrincipal {
        [$type, $id] = PrincipalReference::columns($session);
        $previous    = [IdentifierCoercion::stringify($session->getRawOriginal($type)), IdentifierCoercion::stringify($session->getRawOriginal($id))];
        $switching   = !PrincipalReference::isRecordedOn($session, $admitted->principal);
        $next        = RefreshTokenHasher::successor($presented[0]);

        // Both tokens end with the session, now at its restarted idle deadline,
        // which is never after the absolute one when there is one.
        $session->setAttribute($session->getIdleExpiresAtName(), $deadlines[0]);

        $tokens = $this->issue($admitted, $session, $next, $now);

        if (!$this->store->switchPrincipal($session, $presented[0], $next, $admitted->principal, $switching, $deadlines, $now)) {
            return $this->afterLostSwitch($session, $admitted, $presented, $now);
        }

        return new SwitchedPrincipal(self::exchanged($admitted, $session, $tokens), $previous[0], $previous[1], $switching);
    }

    /**
     * Answer a switch presenting the rotation id the session's current one
     * replaced, inside the grace window: hand back the current credential for
     * the target, writing nothing, only when the session records the target and
     * either its last rotation was a switch (a lost switch response retried) or
     * the token's own principal is the target; anything else is a conflict the
     * client can retry, not a replay.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function retry(EloquentSession&Model $session, Admitted $admitted, #[\SensitiveParameter] array $presented): AuthenticationFailed|SwitchedPrincipal
    {
        $honored = PrincipalReference::isRecordedOn($session, $admitted->principal)
            && (self::isLastRotationASwitch($session) || IdentifierCoercion::matches($admitted->principal->getPrincipalIdentifier(), $presented[1]));

        if (!$honored) {
            return self::refused(FailureReason::ROTATION_CONFLICT, $this->eventContext($session, $admitted));
        }

        $now    = CarbonImmutable::now()->startOfSecond();
        $tokens = $this->issue($admitted, $session, RefreshTokenHasher::successor($presented[0]), $now);
        $type   = PrincipalReference::type($admitted->principal);
        $id     = PrincipalReference::id($admitted->principal);

        return new SwitchedPrincipal(self::exchanged($admitted, $session, $tokens), $type, $id, false);
    }

    /**
     * Judge the presented rotation id again against the row as it now is, after
     * the compare-and-swap missed, read with a lock, by the rules the first
     * judgement used: a retry is answered as `retry()` answers it, a
     * still-current id is a conflict, and anything else fails for its reason, a
     * replay revoking the session. There is never a second swap.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function afterLostSwitch(
        EloquentSession&Model $session,
        Admitted $admitted,
        #[\SensitiveParameter] array $presented,
        CarbonImmutable $now,
    ): AuthenticationFailed|SwitchedPrincipal {
        $fresh = $this->store->reload($session);

        if ($fresh === null) {
            return self::refused(FailureReason::SESSION_UNKNOWN, new EventContext(
                $this->context->name(),
                $this->client,
                sessionId: IdentifierCoercion::stringify($session->getSessionIdentifier()),
            ));
        }

        $verdict = RefreshJudgment::classify($fresh, $presented[0], $now, $this->tokens->lifetimes());

        if ($verdict instanceof FailureReason) {
            return $this->fail($fresh, $verdict, $now);
        }

        $refusal = match (true) {
            $verdict[0] === RotationMatch::CURRENT                  => FailureReason::ROTATION_CONFLICT,
            !SessionOwnership::isOwner($fresh, $admitted->identity) => FailureReason::IDENTITY_UNKNOWN,
            default                                                 => null,
        };

        return $refusal === null
            ? $this->retry($fresh, $admitted->on($fresh), $presented)
            : self::refused($refusal, $this->eventContext($fresh, $admitted));
    }

    /**
     * The session's deadlines after the switch, idle then absolute: the
     * absolute one the earlier of the stored one and the guard's absolute
     * lifetime counted from the sign-in, either alone when the other is absent
     * (so a lifetime set or shortened since then applies, and a switch never
     * extends the session), `null` for neither; and the idle one restarted from
     * `$now` within it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \Carbon\CarbonImmutable, 1: ?\Carbon\CarbonImmutable}
     *
     * @throws \Throwable
     */
    private function deadlines(EloquentSession&Model $session, CarbonImmutable $now): array
    {
        $lifetimes = Container::getInstance()->make(ApplicationPolicy::class)->lifetimes($this->context->name());
        $stored    = $session->getAbsoluteExpiresAt();
        $signedIn  = $session->getSignedInAt();
        $absolute  = $signedIn === null ? $stored?->toImmutable() : $lifetimes->absoluteDeadline($signedIn, $stored);

        return [$lifetimes->idleDeadline($now, $absolute), $absolute];
    }

    /**
     * Issue the pair for the admitted target on the session at `$now`, the
     * refresh token carrying the rotation id.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenPair
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function issue(Admitted $admitted, EloquentSession&Model $session, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now): TokenPair
    {
        return new TokenPair(
            $this->tokens->issueAccessToken($admitted->identity, $admitted->principal, $admitted->tenant, $session, $now),
            $this->tokens->issueRefreshToken($session, $rotationId, $admitted->principal, $now),
        );
    }

    /**
     * The failure of a switch on the session, first revoking the session when
     * the failure proves its refresh token was replayed.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function fail(EloquentSession&Model $session, FailureReason $reason, CarbonImmutable $now): AuthenticationFailed
    {
        if ($reason === FailureReason::ROTATION_REUSE) {
            ($this->revoke)($session, $now);
        }

        return self::refused($reason, $this->eventContext($session));
    }

    /**
     * The context of a switch on the session: the guard, the client, the
     * session and the method it records, and whatever of the identity,
     * principal and tenant the switch resolved. A failure before the owner was
     * read (the row's own state, an owner that no longer loads) is about the
     * row, so it names the owner and principal the row records; a refusal of
     * the target names the principal resolved for it, if any, never the one the
     * session acts as.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused|null  $outcome
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function eventContext(EloquentSession&Model $session, Admitted|Refused|null $outcome = null): EventContext
    {
        return new EventContext(
            $this->context->name(),
            $this->client,
            $outcome?->identity,
            $outcome?->principal,
            $outcome?->tenant,
            $session,
            $session->getSignInMethod(),
            fromSession: $outcome?->identity === null,
        );
    }

    /**
     * Whether the session's last rotation was a switch of principal: the switch
     * and the rotation were recorded at the same second.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isLastRotationASwitch(EloquentSession&Model $session): bool
    {
        $switchedAt = $session->getPrincipalSwitchedAt();

        return $switchedAt !== null && $switchedAt->getTimestamp() === $session->getRefreshRotatedAt()?->getTimestamp();
    }

    /**
     * The exchanged session, as the admitted target, with its new pair.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     */
    private static function exchanged(Admitted $admitted, EloquentSession&Model $session, TokenPair $tokens): ExchangedRefresh
    {
        return new ExchangedRefresh($admitted->identity, $admitted->principal, $session, $tokens, $admitted->tenant, $session->getSignInMethod());
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
