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
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
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
 * Exchanges a session's refresh token for a new pair, revoking the session on a
 * replay.
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

        /** The context of the guard whose refresh tokens the exchange accepts. */
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
     * Exchange a refresh token for a new access and refresh token pair, or the
     * undispatched `AuthenticationFailed` event that reports why it failed.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function exchange(
        #[\SensitiveParameter] Secret|string $refreshToken,
        ClientContext $client,
        int|string|null $expectedSession = null,
    ): AuthenticationFailed|ExchangedRefresh|ReturnedToPending {
        $claims  = $this->tokens->parse($refreshToken, TokenType::REFRESH);
        $subject = new AttemptSubject($this->context->name(), AttemptFlow::REFRESH, IdentifierCoercion::stringify($claims[Claims::SESSION_ID->value] ?? null), null, $client->ip);
        $limiter = Container::getInstance()->make(AttemptLimiter::class);
        $wait    = $limiter->blocked($subject);

        $outcome = $wait === null
            ? $this->exchangeClaims($claims, $client, $expectedSession)
            : $this->refused(FailureReason::RATE_LIMITED, new EventContext($this->context->name(), $client, sessionId: $subject->identifier), $wait);

        if ($outcome instanceof AuthenticationFailed && $wait === null) {
            $limiter->recordFailure($subject);
        }

        return $outcome;
    }

    /**
     * Revoke a session with the given reason, and report whether this call
     * revoked it.
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
     * Run the exchange for the parsed claims in one transaction on the
     * session's connection, refusing a session of another guard first.
     *
     * @param  ?array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh|\SineMacula\Laravel\Authentication\Sessions\ReturnedToPending
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private function exchangeClaims(
        #[\SensitiveParameter] ?array $claims,
        ClientContext $client,
        int|string|null $expectedSession,
    ): AuthenticationFailed|ExchangedRefresh|ReturnedToPending {
        $claims = $this->extractRefreshClaims($claims, $client);

        if ($claims instanceof AuthenticationFailed) {
            return $claims;
        }

        [$rawSessionId, $rotationId, $principalHint] = $claims;

        $record  = SessionLookup::find($rawSessionId);
        $unknown = fn (): AuthenticationFailed => $this->refused(
            FailureReason::SESSION_UNKNOWN,
            new EventContext($this->context->name(), $client, sessionId: IdentifierCoercion::stringify($rawSessionId)),
        );

        if ($record === null) {
            return $unknown();
        }

        $exchange = function () use ($record, $rotationId, $principalHint, $client, $expectedSession, $unknown): AuthenticationFailed|ExchangedRefresh|ReturnedToPending {
            $held = IssuanceGuard::write($record) ? $this->store->reload($record) : null;

            return $held === null
                ? $unknown()
                : $this->exchangeOn($held, $rotationId, $principalHint, CarbonImmutable::now()->startOfSecond(), $client, $expectedSession);
        };

        return WriteConnection::during($record, static fn (): ?string => $record->getGuard()) === $this->context->name()
            ? $record->getConnection()->transaction($exchange)
            : $this->refused(FailureReason::SESSION_GUARD_MISMATCH, $this->sessionContext($client, $record));
    }

    /**
     * Run the exchange on the session of this guard the token names.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $record
     * @param  string  $rotationId
     * @param  mixed  $principalHint
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
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
        int|string|null $expectedSession,
    ): AuthenticationFailed|ExchangedRefresh|ReturnedToPending {
        $verdict = RefreshJudgment::classify($record, $rotationId, $now, $this->tokens->lifetimes());

        if ($verdict instanceof FailureReason) {
            return $this->fail($record, $verdict, $now, $client);
        }

        if ($expectedSession !== null && !IdentifierCoercion::matches($record->getSessionIdentifier(), $expectedSession)) {
            return $this->refused(FailureReason::SESSION_MISMATCH, $this->sessionContext($client, $record));
        }

        $session = $this->hydrateRefreshContext($record, $principalHint, $client);

        return $session instanceof AuthenticationFailed ? $session : $this->underTenantPolicy($record, $session, $verdict, $rotationId, $now, $client);
    }

    /**
     * Judge the admitted session against its tenant's authentication policy,
     * then rotate or reissue when it meets it.
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
        $policy = TenantPolicyCheck::check($this->context->name(), $session, $record, $client, $now, new ProofSource(current: true));

        if (!$policy->isMet()) {
            return $this->fallShort($record, $session, $policy, $rotationId, $now, $client);
        }

        return $verdict[0] === RotationMatch::CURRENT
            ? $this->rotate($record, $session, $rotationId, $now, $verdict[1], $client, $policy->version)
            : $this->reissue($record, $session, $rotationId, $now);
    }

    /**
     * Answer a session that no longer meets its tenant's authentication policy
     * by revoking it or returning it to pending.
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

        $transitions = new PendingTransitions($this->context, $this->afterCommit, Container::getInstance()->make(Repository::class), $client);
        $firstFactor = PendingTransitions::firstFactorOf($record, $policy, current: true);
        $outstanding = $transitions->outstanding($record, $session->identity, $policy->factor, $firstFactor, $now, current: true);

        return $transitions->returnToPending($record, $session, $policy->version, $outstanding, $firstFactor, AuthenticationFlow::REFRESH, $now)
            ?? $this->afterLostRotation($record, $session, $rotationId, $now, $client, true);
    }

    /**
     * Extract and shape-check the refresh-token claims.
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
     * The `AuthenticationFailed` event of a refresh that failed for the reason.
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
     * The context of an exchange on the session, with whatever of its identity,
     * principal and tenant the exchange resolved.
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
     * Revoke the session at the given time, and report it once committed when
     * this call revoked it.
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
     * Report the revocation once it commits when this exchange revoked it, and
     * pass on whether it did.
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
     * Admit the session's identity and principal, which must be the principal
     * the session records.
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

        $tokens = SessionTokens::pair($this->tokens, $session, $record, $next, $now);

        if ($this->store->rotate($record, $rotationId, $next, $idle, $now, $policyVersion)) {
            return self::exchanged($record, $session, $tokens);
        }

        return $this->afterLostRotation($record, $session, $rotationId, $now, $client);
    }

    /**
     * Judge the presented rotation id again against the row as it now is, after
     * the compare-and-swap missed; there is never a second swap.
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
     * Why the presented rotation id, judged again, gets no pair, or `null` when
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
     * Hand a grace retry the session's current credential without writing any
     * rotation state.
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
        return self::exchanged($record, $session, SessionTokens::pair($this->tokens, $session, $record, RefreshTokenHasher::successor($rotationId), $now));
    }

    /**
     * The exchanged session, with its new pair.
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
