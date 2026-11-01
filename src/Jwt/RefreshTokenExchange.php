<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\PendingTransitions;
use SineMacula\Laravel\Authentication\Sessions\ReturnedToPending;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;

/**
 * Refresh-token exchange service.
 *
 * The session's owner is reloaded through the guard's identity provider, so the
 * provider's scopes apply and an owner the guard does not serve is rejected. A
 * token is honoured only for a session of the guard exchanging it, and only
 * while the application policy still lets the method that started the session
 * start one and still admits the owner as the principal; none of these failures
 * revokes the session. The principal the token names must be the one the
 * session records: after the session switched principal, the refresh tokens of
 * the principal it left fail as `session_principal_mismatch`, without revoking
 * the session. The next idle deadline follows the lifetimes the policy gives
 * the guard.
 *
 * Every exchange then asks the authentication policy of the session's active
 * tenant: a session that must have been established through a connection it
 * was not is revoked (`tenant_policy_changed`) and refused as `sso_required`;
 * one that lacks a further factor returns to pending and the exchange hands out
 * a pending credential instead of a pair; one that meets it records the version
 * answered in the rotation.
 *
 * Failed exchanges are counted against the token's session and the client's IP
 * address; once either count is full the exchange is refused as `rate_limited`
 * before the session is looked up.
 *
 * A validly signed token for a live session carries one of three rotation ids:
 * - the current one: the exchange rotates it to its successor with a
 *   compare-and-swap that also moves the session's idle deadline;
 * - the one the current one replaced, inside the grace window: the exchange
 *   hands back the current credential (a fresh pair whose refresh token carries
 *   the current rotation id) and writes no rotation state, so retries
 *   neither extend the window nor disturb the swap;
 * - any other: the token was rotated before, so it is a replay, and the session
 *   is revoked (`rotation_reuse`). A session that holds no refresh credential
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
final readonly class RefreshTokenExchange
{
    /** @var \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore Guarded writes and locking reads of the session's refresh state. */
    private RefreshRotationStore $store;

    /** @var \SineMacula\Laravel\Authentication\Database\AfterCommit Defers `SessionRevoked` until the revocation commits. */
    private AfterCommit $afterCommit;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Closure(): mixed  $transactions
     */
    public function __construct(

        /** Token service for parsing and issuing tokens. */
        private JwtTokenService $tokens,

        /** The context of the guard whose refresh tokens the exchange accepts: its name, provider, resolver and dispatcher. */
        private GuardContext $context,

        // Connection resolver for the session's refresh state writes.
        ConnectionResolverInterface $connections,

        // Returns the current transactions manager, if any, when called.
        \Closure $transactions,
    ) {
        $this->store       = new RefreshRotationStore($connections);
        $this->afterCommit = new AfterCommit($transactions);
    }

    /**
     * Exchange a refresh token for a new access + refresh token pair. On any
     * failure the `AuthenticationFailed` event that reports it is returned, not
     * dispatched, and the failure is counted against the token's session and
     * the client's IP address.
     *
     * Refreshing cannot guess a secret, so only failures are counted. Once
     * either count is full the exchange stops before looking the session up and
     * fails as `rate_limited`, carrying the seconds until the full count's
     * window ends; that failure is not counted itself.
     *
     * @param  string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function exchange(#[\SensitiveParameter] string $refreshToken, ClientContext $client): AuthenticationFailed|ExchangedRefresh|ReturnedToPending
    {
        $claims  = $this->tokens->parse($refreshToken, TokenType::REFRESH);
        $subject = new AttemptSubject($this->context->name(), AttemptFlow::REFRESH, IdentifierCoercion::stringify($claims[Claims::SESSION_ID->value] ?? null), null, $client->ip);
        $limiter = Container::getInstance()->make(AttemptLimiter::class);
        $wait    = $limiter->blocked($subject);

        $outcome = $wait === null
            ? $this->exchangeClaims($claims, $client)
            : $this->refused(FailureReason::RATE_LIMITED, new EventContext($this->context->name(), $client, sessionId: $subject->identifier), $wait);

        if ($outcome instanceof AuthenticationFailed && $wait === null) {
            $limiter->recordFailure($subject);
        }

        return $outcome;
    }

    /**
     * Revoke a session with the given reason: its tokens stop working at once,
     * on the bearer path and on refresh. Idempotent: an already revoked session
     * keeps its first revocation's time and reason. Returns whether this call
     * revoked the session; when it did, the revocation is mirrored on the
     * in-memory session and `SessionRevoked`, carrying the client, is
     * dispatched once the revocation is committed on the session's connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     *
     * @imperative
     */
    public function revokeSession(EloquentSession&Model $record, RevocationReason $reason, ClientContext $client): bool
    {
        return $this->revoke($record, $reason, CarbonImmutable::now()->startOfSecond(), $client);
    }

    /**
     * Run the exchange for the parsed claims: the session the token names, its
     * guard, the rotation id against it, its owner and principal, and the
     * application policy, then the rotation or the grace reissue. Returns the
     * `AuthenticationFailed` event of the first check that fails.
     *
     * @param  ?array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function exchangeClaims(#[\SensitiveParameter] ?array $claims, ClientContext $client): AuthenticationFailed|ExchangedRefresh|ReturnedToPending
    {
        $claims = $this->extractRefreshClaims($claims, $client);

        if ($claims instanceof AuthenticationFailed) {
            return $claims;
        }

        [$rawSessionId, $rotationId, $principalHint] = $claims;

        $record = SessionLookup::find($rawSessionId);

        return $record === null
            ? $this->refused(FailureReason::SESSION_UNKNOWN, new EventContext($this->context->name(), $client, sessionId: IdentifierCoercion::stringify($rawSessionId)))
            : $this->exchangeOn($record, $rotationId, $principalHint, CarbonImmutable::now()->startOfSecond(), $client);
    }

    /**
     * Run the exchange on the session the token names. A session of another
     * guard (or of none), read on the write connection, fails as
     * `session_guard_mismatch` before anything else is judged, so a token of
     * one guard can never revoke another guard's session. A failure that proves
     * a replay revokes the session; no other one does.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  string  $rotationId
     * @param  mixed  $principalHint
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function exchangeOn(
        EloquentSession&Model $record,
        #[\SensitiveParameter] string $rotationId,
        mixed $principalHint,
        CarbonImmutable $now,
        ClientContext $client,
    ): AuthenticationFailed|ExchangedRefresh|ReturnedToPending {
        $guard   = WriteConnection::during($record, static fn (): ?string => $record->getGuard());
        $verdict = $guard === $this->context->name()
            ? RefreshJudgment::classify($record, $rotationId, $now, $this->tokens->lifetimes())
            : FailureReason::SESSION_GUARD_MISMATCH;

        if ($verdict instanceof FailureReason) {
            return $this->fail($record, $verdict, $now, $client);
        }

        $session = $this->hydrateRefreshContext($record, $principalHint, $client);

        if ($session instanceof AuthenticationFailed) {
            return $session;
        }

        return $this->underTenantPolicy($record, $session, $verdict, $rotationId, $now, $client);
    }

    /**
     * Judge the admitted session against its tenant's authentication policy
     * and, when it meets it, rotate the current rotation id (recording the
     * version answered) or hand a grace retry the current credential;
     * otherwise answer the shortfall.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch, 1: ?\Carbon\CarbonInterface}  $verdict
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function underTenantPolicy(
        EloquentSession&Model $record,
        Admitted $session,
        array $verdict,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
        ClientContext $client,
    ): AuthenticationFailed|ExchangedRefresh|ReturnedToPending {
        $policy = TenantPolicyCheck::check($this->context->name(), $session->identity, $session->principal, $session->tenant, $record, $now);

        if (!$policy->isMet()) {
            return $this->fallShort($record, $session, $policy, $rotationId, $now, $client);
        }

        return $verdict[0] === RotationMatch::CURRENT
            ? $this->rotate($record, $session, $rotationId, $now, $verdict[1], $client, $policy->version)
            : $this->reissue($record, $session, $rotationId, $now);
    }

    /**
     * Answer a session that no longer meets its tenant's authentication policy:
     * one that must be established through a connection it was not can never
     * meet it, so it is revoked (`tenant_policy_changed`) and the exchange
     * refused as `sso_required`; one that lacks a further factor returns to
     * pending, recording the version answered, and the client gets a pending
     * credential instead of a pair. Both writes apply only to the row as it was
     * judged: the revocation while it is still active with the refresh digest,
     * principal and active tenant it was loaded with, so a session a concurrent
     * switch moved to another tenant is never revoked for this one. A write
     * that misses judges the row again, as after a lost rotation, but never
     * hands out a pair: the policy this exchange asked said the session falls
     * short.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict  $policy
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function fallShort(
        EloquentSession&Model $record,
        Admitted $session,
        TenantPolicyVerdict $policy,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
        ClientContext $client,
    ): AuthenticationFailed|ExchangedRefresh|ReturnedToPending {
        if ($policy->standing === TenantPolicyStanding::SSO_REQUIRED) {

            $reason  = RevocationReason::TENANT_POLICY_CHANGED;
            $revoked = $this->reported($record, $reason, $client, $this->store->revokeAsLoaded($record, $reason, $now));

            return $revoked
                ? $this->refused(FailureReason::SSO_REQUIRED, $this->sessionContext($client, $record, $session->identity, $session->principal, $session->tenant))
                : $this->afterLostRotation($record, $session, $rotationId, $now, $client, true);
        }

        $transitions = new PendingTransitions($this->context, $this->afterCommit, Container::getInstance()->make(Repository::class));

        return $transitions->returnToPending($record, $session, $policy->version, AuthenticationFlow::REFRESH, $now)
            ?? $this->afterLostRotation($record, $session, $rotationId, $now, $client, true);
    }

    /**
     * Extract and shape-check the refresh-token claims. `parse()` has already
     * rejected a token missing `sid` or `jti`, so what remains is a `jti` that
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
            return $this->refused(FailureReason::TOKEN_INVALID, new EventContext($this->context->name(), $client));
        }

        $rawSessionId  = $claims[Claims::SESSION_ID->value];
        $rotationId    = $claims[Claims::JWT_ID->value];
        $principalHint = $claims[Claims::PRINCIPAL->value] ?? null;

        if (!is_string($rotationId)) {
            return $this->refused(FailureReason::TOKEN_INVALID, new EventContext($this->context->name(), $client, sessionId: is_string($rawSessionId) ? $rawSessionId : null));
        }

        /** @var non-empty-string $rotationId */
        return [$rawSessionId, $rotationId, $principalHint];
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
     * The context of an exchange on the session: the guard exchanging, the
     * client, the session and the method it records, and whatever of the
     * session's identity, principal and tenant the exchange resolved. A failure
     * before the owner was read (the row's own state, an owner that no longer
     * loads) is about the row, so it names the owner and principal the row
     * records.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function sessionContext(
        ClientContext $client,
        EloquentSession&Model $record,
        ?Identity $identity = null,
        ?Principal $principal = null,
        ?Tenant $tenant = null,
    ): EventContext {
        return new EventContext($this->context->name(), $client, $identity, $principal, $tenant, $record, $record->getSignInMethod(), fromSession: $identity === null);
    }

    /**
     * The failure of an exchange on the session, first revoking the session
     * when the failure proves its refresh token was replayed.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function fail(EloquentSession&Model $record, FailureReason $reason, CarbonImmutable $now, ClientContext $client): AuthenticationFailed
    {
        if ($reason === FailureReason::ROTATION_REUSE) {
            $this->revoke($record, RevocationReason::ROTATION_REUSE, $now, $client);
        }

        return $this->refused($reason, $this->sessionContext($client, $record));
    }

    /**
     * Revoke the session at the given time, and report it when this call did,
     * once the revocation is committed on the session's own connection. The
     * event's guard is the session's own.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     *
     * @imperative
     */
    private function revoke(EloquentSession&Model $record, RevocationReason $reason, CarbonImmutable $now, ClientContext $client): bool
    {
        return $this->reported($record, $reason, $client, $this->store->revoke($record, $reason, $now));
    }

    /**
     * Report the revocation of the session when this exchange revoked it, once
     * it is committed on the session's own connection, and pass on whether it
     * did. The event's guard is the session's own.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  bool  $revoked
     * @return bool
     */
    private function reported(EloquentSession&Model $record, RevocationReason $reason, ClientContext $client, bool $revoked): bool
    {
        if ($revoked) {

            $event = new SessionRevoked(new EventContext($record->getGuard(), $client, session: $record, method: $record->getSignInMethod(), fromSession: true), $reason);

            $this->afterCommit->run($record, function () use ($event): void {
                $this->context->dispatch($event);
            });
        }

        return $revoked;
    }

    /**
     * Hydrate identity + principal from a verified session row, and hold them
     * to the application policy (see `RefreshAdmission`); the principal must be
     * the one the session records (`session_principal_mismatch`). Returns what
     * was admitted (the identity, the principal, the session's active tenant,
     * and the session), or the failure with as much of it as was resolved.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  mixed  $principalHint
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function hydrateRefreshContext(EloquentSession&Model $record, mixed $principalHint, ClientContext $client): Admitted|AuthenticationFailed
    {
        $admitted = (new RefreshAdmission($this->context->name(), $this->context->provider(), $this->context->resolver()))->admit($record, $principalHint);

        if ($admitted instanceof Admitted && !PrincipalReference::isRecordedOn($record, $admitted->principal)) {
            $admitted = Refused::after(FailureReason::SESSION_PRINCIPAL_MISMATCH, $admitted);
        }

        return $admitted instanceof Refused
            ? $this->refused($admitted->reason, $this->sessionContext($client, $record, $admitted->identity, $admitted->principal, $admitted->tenant))
            : $admitted;
    }

    /**
     * Rotate the presented current rotation id to its successor and issue the
     * pair for it.
     *
     * The new idle deadline is the idle lifetime the application policy gives
     * the guard, from `$now`, never past the absolute deadline when the session
     * has one, which a rotation never moves (and never adds). Both tokens are
     * issued at `$now`, the time the session was judged at, before anything is
     * written, so a failure while issuing (signing, randomness, an identifier
     * that cannot be read) leaves the presented refresh token valid. The pair
     * is only returned once the compare-and-swap has committed; when the swap
     * misses, the row changed under the exchange and is judged again.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\Carbon\CarbonInterface  $absolute
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $policyVersion
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
        EloquentSession&Model $record,
        Admitted $session,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
        ?CarbonInterface $absolute,
        ClientContext $client,
        ?string $policyVersion,
    ): AuthenticationFailed|ExchangedRefresh {
        $next = RefreshTokenHasher::successor($rotationId);
        $idle = Container::getInstance()->make(ApplicationPolicy::class)->lifetimes($this->context->name())->idleDeadline($now, $absolute);

        $record->setAttribute($record->getIdleExpiresAtName(), $idle);

        $tokens = new TokenPair(
            $this->tokens->issueAccessToken($session->identity, $session->principal, $session->tenant, $record, $now),
            $this->tokens->issueRefreshToken($record, $next, $session->principal, $now),
        );

        if ($this->store->rotate($record, $rotationId, $next, $idle, $now, $policyVersion)) {
            return self::exchanged($record, $session, $tokens);
        }

        return $this->afterLostRotation($record, $session, $rotationId, $now, $client);
    }

    /**
     * Judge the presented rotation id again against the row as it now is, after
     * the compare-and-swap missed, with the same `$now`. There is never a
     * second swap.
     *
     * The usual cause is a parallel refresh with the same token that rotated
     * first; its successor is this exchange's, so this one is a grace retry and
     * gets the current credential. A replay is revoked, and a session that was
     * revoked, deleted, or ended in between fails for that reason. A token that
     * is still the current one means other security state changed in between (a
     * deadline, say): that proves nothing, so it fails as `rotation_conflict`
     * without revoking, and the client can retry. Before any success the fresh
     * row must still belong to the identity the exchange hydrated and still
     * record the principal and the active tenant it admitted: a switch that won
     * the swap moved the session to a context this exchange never judged, so
     * its retry fails as `session_principal_mismatch` or
     * `session_tenant_mismatch` instead. When the write that missed was for a
     * session this exchange found short of its tenant's policy, a grace retry
     * fails as `rotation_conflict` instead of getting the pair that policy
     * refused it, and the client's next refresh is judged afresh.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  bool  $fellShort
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
        EloquentSession&Model $record,
        Admitted $session,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
        ClientContext $client,
        bool $fellShort = false,
    ): AuthenticationFailed|ExchangedRefresh {
        $fresh = $this->store->reload($record);

        if ($fresh === null) {

            $context = new EventContext($this->context->name(), $client, sessionId: IdentifierCoercion::stringify($record->getSessionIdentifier()));

            return $this->refused(FailureReason::SESSION_UNKNOWN, $context);
        }

        $verdict = RefreshJudgment::classify($fresh, $rotationId, $now, $this->tokens->lifetimes());
        $refusal = is_array($verdict) ? self::retryRefusal($fresh, $session, $verdict[0], $fellShort) : $verdict;

        return $refusal === null
            ? $this->reissue($fresh, $session, $rotationId, $now)
            : $this->fail($fresh, $refusal, $now, $client);
    }

    /**
     * Why the presented rotation id, judged again as still current or as a
     * grace retry of the fresh row, gets no pair: still current, it is a
     * conflict; a retry must find the row still the hydrated identity's,
     * recording the principal and active tenant admitted, and not follow a
     * write for a session that fell short of its tenant's policy. `null` when
     * the retry gets the current credential.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $fresh
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch  $match
     * @param  bool  $fellShort
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private static function retryRefusal(EloquentSession&Model $fresh, Admitted $session, RotationMatch $match, bool $fellShort): ?FailureReason
    {
        return match (true) {
            $match === RotationMatch::CURRENT                                       => FailureReason::ROTATION_CONFLICT,
            !SessionOwnership::isOwner($fresh, $session->identity)                  => FailureReason::IDENTITY_UNKNOWN,
            !PrincipalReference::isRecordedOn($fresh, $session->principal)          => FailureReason::SESSION_PRINCIPAL_MISMATCH,
            !OwnedSession::actsIn($fresh, $session->tenant?->getTenantIdentifier()) => FailureReason::SESSION_TENANT_MISMATCH,
            $fellShort                                                              => FailureReason::ROTATION_CONFLICT,
            default                                                                 => null,
        };
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
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
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
    private function reissue(EloquentSession&Model $record, Admitted $session, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now): ExchangedRefresh
    {
        $tokens = new TokenPair(
            $this->tokens->issueAccessToken($session->identity, $session->principal, $session->tenant, $record, $now),
            $this->tokens->issueRefreshToken($record, RefreshTokenHasher::successor($rotationId), $session->principal, $now),
        );

        return self::exchanged($record, $session, $tokens);
    }

    /**
     * The exchanged session, with its new pair: the identity, principal and
     * tenant it was admitted as, and the method the session records.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $session
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenPair  $tokens
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     */
    private static function exchanged(EloquentSession&Model $record, Admitted $session, TokenPair $tokens): ExchangedRefresh
    {
        return new ExchangedRefresh($session->identity, $session->principal, $record, $tokens, $session->tenant, $record->getSignInMethod());
    }
}
