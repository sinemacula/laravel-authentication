<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
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
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshJudgment;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Proves, from a refresh token, the session of one guard the client holds now,
 * without rotating it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshProof
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore  $store
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     */
    public function __construct(

        /** The context of the guard whose sessions the token may prove. */
        private GuardContext $context,

        /** The guard's token service, which parses the token. */
        private JwtTokenService $tokens,

        /** Revokes a session whose token was replayed. */
        private RefreshRotationStore $store,

        /** Defers the report of a replay's revocation until it commits. */
        private AfterCommit $afterCommit,
    ) {}

    /**
     * The session the refresh token proves the client holds now, or the
     * undispatched `AuthenticationFailed` event that reports why it proves
     * none.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\ProvenRefresh
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function prove(
        #[\SensitiveParameter] Secret|string $refreshToken,
        AuthenticationFlow $flow,
        CarbonImmutable $now,
        ClientContext $client,
    ): AuthenticationFailed|ProvenRefresh {
        $named = $this->named($this->tokens->parse($refreshToken, TokenType::REFRESH), $flow, $client);

        if ($named instanceof AuthenticationFailed) {
            return $named;
        }

        [$session, $rotationId, $principalHint] = $named;

        $judged = $this->judged($session, $rotationId, $principalHint, $now, $client);

        if ($judged instanceof FailureReason) {
            return new AuthenticationFailed(
                new EventContext($this->context->name(), $client, session: $session, method: $session->getSignInMethod(), fromSession: true),
                $flow,
                $judged,
            );
        }

        return new ProvenRefresh($session, $principalHint, $judged);
    }

    /**
     * The session the token's claims name, with the rotation id and principal
     * they carry, or the refusal.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  ?array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: string, 2: mixed}|\SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function named(#[\SensitiveParameter] ?array $claims, AuthenticationFlow $flow, ClientContext $client): array|AuthenticationFailed
    {
        $sessionId  = $claims[Claims::SESSION_ID->value] ?? null;
        $rotationId = $claims[Claims::JWT_ID->value]     ?? null;

        if ($claims === null || !is_string($rotationId)) {
            return $this->refused($flow, FailureReason::TOKEN_INVALID, is_string($sessionId) ? $sessionId : null, $client);
        }

        $session = SessionLookup::find($sessionId);

        return $session === null
            ? $this->refused($flow, FailureReason::SESSION_UNKNOWN, IdentifierCoercion::stringify($sessionId), $client)
            : [$session, $rotationId, $claims[Claims::PRINCIPAL->value] ?? null];
    }

    /**
     * The refusal of a token that names no session found, about the session id
     * it names, if any.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function refused(AuthenticationFlow $flow, FailureReason $reason, ?string $sessionId, ClientContext $client): AuthenticationFailed
    {
        return new AuthenticationFailed(new EventContext($this->context->name(), $client, sessionId: $sessionId), $flow, $reason);
    }

    /**
     * Judge the session the token names, revoking it on a replay; returns the
     * refusal or which rotation id the token carried.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $rotationId
     * @param  mixed  $principalHint
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch
     */
    private function judged(
        EloquentSession&Model $session,
        #[\SensitiveParameter] string $rotationId,
        mixed $principalHint,
        CarbonImmutable $now,
        ClientContext $client,
    ): FailureReason|RotationMatch {
        if (WriteConnection::during($session, static fn (): ?string => $session->getGuard()) !== $this->context->name()) {
            return FailureReason::SESSION_GUARD_MISMATCH;
        }

        $verdict = RefreshJudgment::classify($session, $rotationId, $now, $this->tokens->lifetimes());

        if ($verdict === FailureReason::ROTATION_REUSE) {
            $this->revoke($session, $now, $client);
        }

        if ($verdict instanceof FailureReason) {
            return $verdict;
        }

        [, $id] = PrincipalReference::columns($session);

        return $principalHint !== null && !IdentifierCoercion::matches($session->getRawOriginal($id), $principalHint)
            ? FailureReason::SESSION_PRINCIPAL_MISMATCH
            : $verdict[0];
    }

    /**
     * Revoke the session whose token was replayed, and report it once the
     * revocation commits.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    private function revoke(EloquentSession&Model $session, CarbonImmutable $now, ClientContext $client): void
    {
        if (!$this->store->revoke($session, RevocationReason::ROTATION_REUSE, $now)) {
            return;
        }

        $event = new SessionRevoked(
            new EventContext($session->getGuard(), $client, session: $session, method: $session->getSignInMethod(), fromSession: true),
            RevocationReason::ROTATION_REUSE,
        );

        $this->afterCommit->run($session, fn () => $this->context->dispatch($event));
    }
}
