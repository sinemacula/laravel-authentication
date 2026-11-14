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
use SineMacula\Laravel\Authentication\Jwt\SessionTokens;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Switches a session to another principal of the same identity, another active
 * tenant, or both, proven by the session's refresh token.
 *
 * Never by an access token: a stolen short-lived one must not mint a refresh
 * credential.
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
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @param  int|string|null  $expectedSession
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

        /** Checks the principal and tenant the switch moved the session to once it commits. */
        private AdmissionRecheck $recheck,

        /** The id of the session the token must prove, or `null` to accept any. */
        private int|string|null $expectedSession = null,
    ) {}

    /**
     * Switch the session the refresh token proves to the target.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    public function switch(#[\SensitiveParameter] Secret|string $refreshToken): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal
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
     * Run the switch for the parsed claims on the session they name, in one
     * transaction on its connection.
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
        $unknown   = fn (): AuthenticationFailed => self::refused(
            FailureReason::SESSION_UNKNOWN,
            new EventContext($this->context->name(), $this->client, sessionId: IdentifierCoercion::stringify($sessionId)),
        );

        if ($session === null) {
            return $unknown();
        }

        $presented = [$rotationId, $claims[Claims::PRINCIPAL->value] ?? null];
        $switch    = function () use ($session, $presented, $unknown): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal {
            $held = IssuanceGuard::write($session) ? $this->store->reload($session) : null;

            return $held === null ? $unknown() : $this->switchOn($held, $presented);
        };

        return WriteConnection::during($session, static fn (): ?string => $session->getGuard()) === $this->context->name()
            ? $session->getConnection()->transaction($switch)
            : self::refused(FailureReason::SESSION_GUARD_MISMATCH, $this->eventContext($session));
    }

    /**
     * Run the switch on the session of this guard the token names.
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
        $verdict = RefreshJudgment::classify($session, $presented[0], $now, $this->tokens->lifetimes());

        if ($verdict instanceof FailureReason) {
            return $this->fail($session, $verdict, $now);
        }

        if ($this->expectedSession !== null && !IdentifierCoercion::matches($session->getSessionIdentifier(), $this->expectedSession)) {
            return self::refused(FailureReason::SESSION_MISMATCH, $this->eventContext($session));
        }

        $admitted = $this->admit($session);

        return match (true) {
            $admitted instanceof AuthenticationFailed => $admitted,
            $verdict[0] === RotationMatch::CURRENT    => $this->switchCurrent($session, $admitted, $presented, $now),
            default                                   => $this->retry($session, $admitted, $presented),
        };
    }

    /**
     * Admit the destination for the session: its owner, as the destination
     * principal, in the destination tenant.
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
     * may switch to, in the destination tenant.
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
     * Whether the principal the hinted path resolved is the very destination,
     * owned by the session's owner.
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
     * Switch the session presenting its current rotation id.
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
     * refusing, returning it to pending, or letting the switch rotate.
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
        $source  = new ProofSource(current: true);
        $verdict = TenantPolicyCheck::check($this->context->name(), $destination, $session, $this->client, $now, $source);
        $missed  = fn (): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal => $this->afterLostSwitch($session, $destination, $presented, $now);

        return match ($verdict->standing) {
            TenantPolicyStanding::SSO_REQUIRED    => self::refused(FailureReason::SSO_REQUIRED, $this->eventContext($session, $destination)),
            TenantPolicyStanding::FACTOR_REQUIRED => $this->toPending($session, $destination, $verdict, $now, $missed),
            TenantPolicyStanding::MET             => $this->rotateTo($session, $destination, $presented, [$deadlines, $verdict->version], $now),
        };
    }

    /**
     * Return the session to pending with the destination recorded, or answer a
     * missed compare-and-swap as the caller has it answered.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict  $verdict
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(): (\SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal)  $missed
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function toPending(
        EloquentSession&Model $session,
        Admitted $destination,
        TenantPolicyVerdict $verdict,
        CarbonImmutable $now,
        \Closure $missed,
    ): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal {
        $firstFactor = PendingTransitions::firstFactorOf($session, $verdict, current: true);
        $outstanding = $this->transitions->outstanding($session, $destination->identity, $verdict->factor, $firstFactor, $now, current: true);
        $changes     = RefreshRotationStore::contextChanges($session, $destination);
        $transition  = $this->transitions->reportingThrough(function (\Closure $report) use ($session, $destination, $changes): void {

            $this->recheck->switch($session, $destination, ...$changes);
            $this->recheck->then($session, $report);
        });

        return $transition->returnToPending($session, $destination, $verdict->version, $outstanding, $firstFactor, AuthenticationFlow::SWITCH, $now) ?? $missed();
    }

    /**
     * Issue the pair for the destination before the one compare-and-swap that
     * records the switch.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  array{0: string, 1: mixed}  $presented
     * @param  array{0: array{0: \Carbon\CarbonImmutable, 1: ?\Carbon\CarbonImmutable}, 1: ?string}  $answered
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function rotateTo(
        EloquentSession&Model $session,
        Admitted $destination,
        #[\SensitiveParameter] array $presented,
        array $answered,
        CarbonImmutable $now,
    ): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal {
        [$deadlines, $version] = $answered;
        [$type, $id]           = PrincipalReference::columns($session);
        [$principal, $tenant]  = RefreshRotationStore::contextChanges($session, $destination);

        $previous = [
            IdentifierCoercion::stringify($session->getRawOriginal($type)),
            IdentifierCoercion::stringify($session->getRawOriginal($id)),
            IdentifierCoercion::stringify($session->getRawOriginal($session->getTenantIdName())),
        ];

        $next = RefreshTokenHasher::successor($presented[0]);

        // Both tokens end at the session's restarted idle deadline and name the
        // tenant it is to act in.
        $session->setAttribute($session->getIdleExpiresAtName(), $deadlines[0]);
        $session->setAttribute($session->getTenantIdName(), IdentifierCoercion::stringify($destination->tenant?->getTenantIdentifier()));

        $tokens = $this->issue($destination, $session, $next, $now);

        if (!$this->store->switchSession($session, [$presented[0], $next], $destination, $version, $deadlines, $now)) {
            return $this->afterLostSwitch($session, $destination, $presented, $now);
        }

        $this->recheck->switch($session, $destination, $principal, $tenant);

        return new SwitchedPrincipal(self::exchanged($destination, $session, $tokens), $previous[0], $previous[1], $previous[2], $principal, $tenant);
    }

    /**
     * Answer a switch presenting the rotation id the session's current one
     * replaced, inside the grace window.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function retry(EloquentSession&Model $session, Admitted $admitted, #[\SensitiveParameter] array $presented): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal
    {
        $honored = !in_array(true, RefreshRotationStore::contextChanges($session, $admitted), true)
            && (self::isLastRotationASwitch($session) || IdentifierCoercion::matches($admitted->principal->getPrincipalIdentifier(), $presented[1]));

        if (!$honored) {
            return self::refused(FailureReason::ROTATION_CONFLICT, $this->eventContext($session, $admitted));
        }

        $now     = CarbonImmutable::now()->startOfSecond();
        $verdict = TenantPolicyCheck::check($this->context->name(), $admitted, $session, $this->client, $now, new ProofSource(current: true));
        $missed  = fn (): AuthenticationFailed => self::refused(FailureReason::ROTATION_CONFLICT, $this->eventContext($session, $admitted));

        return match ($verdict->standing) {
            TenantPolicyStanding::SSO_REQUIRED    => self::refused(FailureReason::SSO_REQUIRED, $this->eventContext($session, $admitted)),
            TenantPolicyStanding::FACTOR_REQUIRED => $this->toPending($session, $admitted, $verdict, $now, $missed),
            TenantPolicyStanding::MET             => new SwitchedPrincipal(
                self::exchanged($admitted, $session, $this->issue($admitted, $session, RefreshTokenHasher::successor($presented[0]), $now)),
                PrincipalReference::type($admitted->principal),
                PrincipalReference::id($admitted->principal),
                IdentifierCoercion::stringify($admitted->tenant?->getTenantIdentifier()),
                false,
                false,
            ),
        };
    }

    /**
     * Judge the presented rotation id again against the locked row after the
     * compare-and-swap missed.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  array{0: string, 1: mixed}  $presented
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending|\SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal
     *
     * @throws \Throwable
     */
    private function afterLostSwitch(
        EloquentSession&Model $session,
        Admitted $admitted,
        #[\SensitiveParameter] array $presented,
        CarbonImmutable $now,
    ): AuthenticationFailed|ReturnedToPending|SwitchedPrincipal {
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
     * The session's deadlines after the switch, idle then absolute; a switch
     * never extends the absolute one.
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
        return SessionTokens::pair($this->tokens, $admitted, $session, $rotationId, $now);
    }

    /**
     * The failure of a switch on the session, first revoking it when the
     * failure proves a replay.
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
     * The context of a switch on the session, naming whatever of the identity,
     * principal and tenant the switch resolved.
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
     * principal or active tenant.
     *
     * `SwitchFloor` may push the floor past the rotation's second, so the two
     * are compared by order.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isLastRotationASwitch(EloquentSession&Model $session): bool
    {
        $switchedAt = $session->getSwitchedAt();
        $rotatedAt  = $session->getRefreshRotatedAt();

        return $switchedAt !== null && $rotatedAt !== null && $switchedAt->getTimestamp() >= $rotatedAt->getTimestamp();
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
