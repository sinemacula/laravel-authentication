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
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
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
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Switches a session to another principal of the same identity, another active
 * tenant, or both, proven by the session's refresh token (never by an access
 * token: a stolen short-lived access token must not mint a refresh credential).
 *
 * The token is judged as a refresh judges it, counted against the same refresh
 * limits, and a replayed one revokes the session. Every live check runs on
 * every path: the owner, reloaded through the guard's provider and active; the
 * destination principal (the target, or for a tenant-only switch the one the
 * session records), resolved through the hinted path as the very principal
 * named, owned, active, in an active tenant of its own, allowed the application
 * by `ApplicationAccess`, and admitted by the application policy with the type
 * of identifier the session's sign-in used; the session's sign-in method still
 * allowed; the destination tenant (the one selected, or the principal's
 * default) one `TenantAccess` lets the principal act in, and active; then the
 * destination tenant's authentication policy, judged against the session's own
 * proofs and provenance. A policy that requires connections the session was not
 * established through refuses the switch (`sso_required`); one that asks for a
 * further factor the session lacks returns the session to pending with the
 * destination recorded, instead of re-issuing its pair.
 *
 * A switch keeps the session's key, so its proofs and provenance carry over
 * unchanged, and its absolute clock (it never extends the absolute deadline: it
 * keeps it, or lowers it to the guard's absolute lifetime counted from the
 * sign-in, which also gives a session that had none a deadline once the guard
 * sets a limit), restarts the idle one, and writes in one compare-and-swap.
 * When the principal or the tenant changes, that write also moves the session's
 * `switched_at`, so every access token issued before it is refused at once.
 *
 * One switch is one instance, built with the guard's context, the client and
 * the target when the switch runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionSwitch
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore  $store
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \Carbon\CarbonImmutable): bool  $revoke
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingTransitions  $transitions
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

        /** Where the session is to switch to. */
        private SwitchTarget $target,

        /** Revokes a session whose refresh token was replayed, and reports it. */
        private \Closure $revoke,

        /** Returns the session to pending when its destination asks for a further factor it lacks. */
        private PendingTransitions $transitions,
    ) {}

    /**
     * Switch the session the refresh token proves to the target. Returns the
     * switched session, the session returned to pending, or the
     * `AuthenticationFailed` event that reports why it was refused,
     * undispatched. A failure is counted against the token's session and the
     * client's IP address; once either count is full the switch is refused as
     * `rate_limited` before the session is looked up.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    public function switch(#[\SensitiveParameter] string $refreshToken): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal
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
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function switchClaims(#[\SensitiveParameter] ?array $claims): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal
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
     * against it, the destination's admission, then the switch or the retry.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  array{0: string, 1: mixed}  $presented
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function switchOn(EloquentSession&Model $session, #[\SensitiveParameter] array $presented): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal
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
     * Admit the destination for the session: the session's owner, active, as
     * the destination principal resolved through the hinted path (the very
     * principal named, owned, active, in an active tenant of its own, allowed
     * the application), with the session's sign-in method still allowed, then
     * as the destination the session's sign-in could have chosen, in the
     * destination tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     *
     * @throws \Throwable
     */
    private function admit(EloquentSession&Model $session): Admitted|AuthenticationFailed
    {
        [, $id] = PrincipalReference::columns($session);
        $hint   = $this->target->principal === null ? $session->getRawOriginal($id) : $this->target->principal->getPrincipalIdentifier() ?? '';

        $admitted = (new RefreshAdmission($this->context->name(), $this->context->provider(), $this->context->resolver()))
            ->admitPrincipal($session, $hint);

        if ($admitted instanceof Admitted) {
            $admitted = $this->admitAsDestination($admitted, $session);
        }

        return $admitted instanceof Refused
            ? self::refused($admitted->reason, $this->eventContext($session, $admitted))
            : $admitted;
    }

    /**
     * Hold the admitted principal to what makes it the destination the session
     * may switch to, in the destination tenant: it must be the very principal
     * the switch names (`principal_mismatch`); the application policy must
     * admit the identity with the type of identifier the session's sign-in
     * used, as that sign-in was admitted, so a policy that refuses such an
     * identifier (an unverified one, say) refuses the switch for its reason;
     * and the tenant selected, or the principal's default, must be one
     * `TenantAccess` lets it act in, and active (`tenant_ineligible`,
     * `tenant_inactive`). A session whose sign-in used no identifier is not
     * held to an identifier type. The type is read on the write connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Throwable
     */
    private function admitAsDestination(Admitted $admitted, EloquentSession&Model $session): Admitted|Refused
    {
        if (!$this->isDestination($admitted, $session)) {
            return new Refused(FailureReason::PRINCIPAL_MISMATCH, $admitted->identity);
        }

        $type    = WriteConnection::during($session, static fn (): ?string => $session->getSignInIdentifierType());
        $policy  = Container::getInstance()->make(ApplicationPolicy::class);
        $refusal = $type === null ? null : ApplicationAdmission::admitIdentifier($policy, $this->context->name(), $admitted->identity, $type);
        $tenant  = $refusal ?? TenantAdmission::select($admitted->principal, $this->target->tenant ?? TenantSelection::principalDefault());

        return $tenant instanceof FailureReason
            ? Refused::after($tenant, $admitted)
            : new Admitted($admitted->identity, $admitted->principal, $tenant, $session);
    }

    /**
     * Whether the principal the hinted path resolved (whose identifier the
     * admission already matched to the hint) is the very destination: of the
     * target's class, or for a tenant-only switch the principal the session
     * records, and owned by the session's owner, read from the principal's own
     * stored key rather than trusted to the resolver.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     */
    private function isDestination(Admitted $admitted, EloquentSession&Model $session): bool
    {
        $named = $this->target->principal === null
            ? PrincipalReference::isRecordedOn($session, $admitted->principal)
            : $admitted->principal::class === $this->target->principal::class;

        return $named && PinnedPrincipal::isOwnedBy($admitted->principal, $admitted->identity);
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
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function switchCurrent(
        EloquentSession&Model $session,
        Admitted $admitted,
        #[\SensitiveParameter] array $presented,
        CarbonImmutable $now,
    ): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal {
        [, $id]    = PrincipalReference::columns($session);
        $deadlines = $this->deadlines($session, $now);

        $refusal = match (true) {
            !IdentifierCoercion::matches($session->getRawOriginal($id), $presented[1])      => FailureReason::SESSION_PRINCIPAL_MISMATCH,
            $deadlines[1] !== null && $deadlines[1]->getTimestamp() <= $now->getTimestamp() => FailureReason::SESSION_EXPIRED,
            default                                                                         => null,
        };

        return $refusal === null
            ? $this->underPolicy($session, $admitted, $presented, $deadlines, $now)
            : self::refused($refusal, $this->eventContext($session, $admitted));
    }

    /**
     * Judge the session against the destination tenant's authentication policy,
     * with its own proofs and provenance: one that requires connections the
     * session was not established through refuses the switch (`sso_required`),
     * leaving the session as it was; one that asks for a further factor the
     * session lacks returns the session to pending with the destination
     * recorded, a lost compare-and-swap judged again as after a lost switch;
     * one the session meets lets the switch rotate.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  array{0: string, 1: mixed}  $presented
     * @param  array{0: \Carbon\CarbonImmutable, 1: ?\Carbon\CarbonImmutable}  $deadlines
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function underPolicy(
        EloquentSession&Model $session,
        Admitted $destination,
        #[\SensitiveParameter] array $presented,
        array $deadlines,
        CarbonImmutable $now,
    ): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal {
        $verdict = TenantPolicyCheck::check($this->context->name(), $destination->identity, $destination->principal, $destination->tenant, $session, $now);

        return match ($verdict->standing) {
            TenantPolicyStanding::SSO_REQUIRED    => self::refused(FailureReason::SSO_REQUIRED, $this->eventContext($session, $destination)),
            TenantPolicyStanding::FACTOR_REQUIRED => $this->toPending($session, $destination, $presented, $now),
            TenantPolicyStanding::MET             => $this->rotateTo($session, $destination, $presented, [$deadlines, $verdict->version], $now),
        };
    }

    /**
     * Return the session to pending with the destination recorded, instead of
     * re-issuing its pair, or, when the compare-and-swap missed, judge the
     * presented rotation id again as after a lost switch.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  array{0: string, 1: mixed}  $presented
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function toPending(
        EloquentSession&Model $session,
        Admitted $destination,
        #[\SensitiveParameter] array $presented,
        CarbonImmutable $now,
    ): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal {
        return $this->transitions->returnToPending($session, $destination, AuthenticationFlow::SWITCH, $now)
            ?? $this->afterLostSwitch($session, $destination, $presented, $now);
    }

    /**
     * Issue the pair for the destination before the one compare-and-swap that
     * records the switch, the rotation, the deadlines and the policy version.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  array{0: string, 1: mixed}  $presented
     * @param  array{0: array{0: \Carbon\CarbonImmutable, 1: ?\Carbon\CarbonImmutable}, 1: ?string}  $answered
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function rotateTo(
        EloquentSession&Model $session,
        Admitted $destination,
        #[\SensitiveParameter] array $presented,
        array $answered,
        CarbonImmutable $now,
    ): AuthenticationFailed|SwitchedPrincipal {
        [$deadlines, $version] = $answered;
        [$type, $id]           = PrincipalReference::columns($session);
        [$principal, $tenant]  = RefreshRotationStore::contextChanges($session, $destination);

        $previous = [
            IdentifierCoercion::stringify($session->getRawOriginal($type)),
            IdentifierCoercion::stringify($session->getRawOriginal($id)),
            IdentifierCoercion::stringify($session->getRawOriginal($session->getTenantIdName())),
        ];

        $next = RefreshTokenHasher::successor($presented[0]);

        // Both tokens end with the session, now at its restarted idle deadline,
        // which is never after the absolute one when there is one, and name the
        // tenant it is to act in.
        $session->setAttribute($session->getIdleExpiresAtName(), $deadlines[0]);
        $session->setAttribute($session->getTenantIdName(), IdentifierCoercion::stringify($destination->tenant?->getTenantIdentifier()));

        $tokens = $this->issue($destination, $session, $next, $now);

        if (!$this->store->switchSession($session, [$presented[0], $next], $destination, $version, $deadlines, $now)) {
            return $this->afterLostSwitch($session, $destination, $presented, $now);
        }

        return new SwitchedPrincipal(self::exchanged($destination, $session, $tokens), $previous[0], $previous[1], $previous[2], $principal, $tenant);
    }

    /**
     * Answer a switch presenting the rotation id the session's current one
     * replaced, inside the grace window: hand back the current credential for
     * the destination, writing nothing, only when the session records the
     * destination principal and tenant and either its last rotation was a
     * switch (a lost switch response retried) or the token's own principal is
     * the destination; anything else is a conflict the client can retry, not a
     * replay. The destination tenant's policy is not asked again: the call that
     * recorded the destination asked it.
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
        $honored = !in_array(true, RefreshRotationStore::contextChanges($session, $admitted), true)
            && (self::isLastRotationASwitch($session) || IdentifierCoercion::matches($admitted->principal->getPrincipalIdentifier(), $presented[1]));

        if (!$honored) {
            return self::refused(FailureReason::ROTATION_CONFLICT, $this->eventContext($session, $admitted));
        }

        $now    = CarbonImmutable::now()->startOfSecond();
        $tokens = $this->issue($admitted, $session, RefreshTokenHasher::successor($presented[0]), $now);
        $type   = PrincipalReference::type($admitted->principal);
        $id     = PrincipalReference::id($admitted->principal);
        $tenant = IdentifierCoercion::stringify($admitted->tenant?->getTenantIdentifier());

        return new SwitchedPrincipal(self::exchanged($admitted, $session, $tokens), $type, $id, $tenant, false, false);
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
     * Issue the pair for the admitted destination on the session at `$now`, the
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
     * row, so it names the owner, principal and tenant the row records; a
     * refusal of the destination names the principal and tenant resolved for
     * it, if any, never the ones the session acts as.
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
     * Whether the session's last rotation was a switch that changed its
     * principal or active tenant: the switch and the rotation were recorded at
     * the same second.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isLastRotationASwitch(EloquentSession&Model $session): bool
    {
        $switchedAt = $session->getSwitchedAt();

        return $switchedAt !== null && $switchedAt->getTimestamp() === $session->getRefreshRotatedAt()?->getTimestamp();
    }

    /**
     * The exchanged session, as the admitted destination, with its new pair.
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
        return new AuthenticationFailed($context, AuthenticationFlow::SWITCH, $reason, retryAfter: $retryAfter);
    }
}
