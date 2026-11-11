<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionGeneration;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;

/**
 * Reauthenticates a session of one guard with its identity's first factor,
 * recording the proof and issuing a new access token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionReauthentication
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\ProofIssuance  $issuance
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions are reauthenticated. */
        private GuardContext $context,

        /** Records the proof and issues the new access token. */
        private ProofIssuance $issuance,

        /** Defers `Reauthenticated` until the proof commits. */
        private AfterCommit $afterCommit,

        /** Container the sign-in methods, the application policy and the attempt limiter are resolved from. */
        private Container $container,
    ) {}

    /**
     * Reauthenticate the session with the named method and the input the client
     * sent.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function reauthenticate(Session $session, string $method, #[\SensitiveParameter] array $input, ClientContext $client): AccessTokenResult
    {
        SessionPreconditions::assertSessionMethod($method);

        $now    = CarbonImmutable::now()->startOfSecond();
        $policy = CredentialAttempt::checkMethod($this->container, $this->context->name(), $method);

        if ($policy instanceof Refused) {
            return $this->fail($policy, $method, null, $client);
        }

        $challenge = $this->challengeOf($method, $input);
        $outcome   = $this->verified($session, $policy, $method, $input, $now, $client);

        if ($outcome instanceof Refused) {
            return $this->fail($outcome, $method, $challenge, $client);
        }

        [$stored, $factor, $at, $attempt] = $outcome;

        $proof   = new NewProof(ProofKind::FIRST_FACTOR_REAUTHENTICATION, Purpose::REAUTHENTICATE, $method, $factor->channel, null, $factor->observed, null, $factor->methods, $at);
        $accepts = static fn (EloquentSession&Model $row): ?FailureReason => self::isSessionVerified($row, $factor->identity, $stored) ? null : FailureReason::SESSION_UNKNOWN;
        $issued  = $this->issuance->issue($stored->getSessionIdentifier(), $proof, $accepts);

        if ($issued instanceof Refused) {
            $refused = $issued->reason === FailureReason::SESSION_UNKNOWN ? new Refused(FailureReason::SESSION_UNKNOWN, session: $stored) : $issued;

            return $this->fail($refused, $method, $challenge, $client);
        }

        [$admitted, $record, $token, $expires] = $issued;

        $attempt->release();

        $event = new Reauthenticated(new EventContext($this->context->name(), $client, $admitted->identity, $admitted->principal, $admitted->tenant, $record, $method));

        $this->afterCommit->run($record, fn () => $this->context->dispatch($event));

        return AccessTokenResult::issued($token, $record, $expires);
    }

    /**
     * Check the session, take the attempt's slot, and verify the input for the
     * session's owner, or answer the refusal.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \SineMacula\Laravel\Authentication\Proofs\FirstFactor, 2: \Carbon\CarbonImmutable, 3: \SineMacula\Laravel\Authentication\Sessions\CredentialAttempt}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function verified(
        Session $session,
        ApplicationPolicy $policy,
        string $method,
        #[\SensitiveParameter] array $input,
        CarbonImmutable $now,
        ClientContext $client,
    ): array|Refused {
        $guard  = $this->context->name();
        $stored = self::stored($session);
        $live   = $stored === null ? FailureReason::SESSION_UNKNOWN : OwnedSession::refusal($stored, $guard, $now);

        if ($stored === null || $live !== null || SessionOwnership::isMachineOwned($stored)) {
            return new Refused($live ?? FailureReason::MACHINE_IDENTITY, session: $stored);
        }

        $driver  = $this->container->make(SignInMethodManager::class)->method($method);
        $subject = new AttemptSubject($guard, AttemptFlow::SIGN_IN, $driver->identifier($guard, $input), $driver->identifierType($guard), $client->ip);
        $attempt = CredentialAttempt::begin($this->container->make(AttemptLimiter::class), $policy, $subject);

        if ($attempt instanceof Refused) {
            return new Refused($attempt->reason, session: $stored, retryAfter: $attempt->retryAfter);
        }

        $request = new SignInRequest($guard, $this->context->provider(), $input, $client, $attempt->accounts->reserve(...));

        $factor = $this->context->timebox()->run(fn (Timebox $timebox): FailureReason|FirstFactor => $this->verify($driver, $request, $attempt, $stored, $timebox));

        return $factor instanceof FirstFactor
            ? [$stored, $factor, CarbonImmutable::now()->startOfSecond(), $attempt]
            : new Refused($factor, session: $stored, retryAfter: $attempt->accountRefusal()?->retryAfter);
    }

    /**
     * Verify the input with the method for the session's owner, cutting the
     * timebox short only when it verified.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @param  \SineMacula\Laravel\Authentication\Sessions\CredentialAttempt  $attempt
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Illuminate\Support\Timebox  $timebox
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\FirstFactor
     *
     * @throws \LogicException
     */
    private function verify(SignInMethod $driver, SignInRequest $request, CredentialAttempt $attempt, EloquentSession&Model $session, Timebox $timebox): FailureReason|FirstFactor
    {
        $verified = $driver->authenticate($request);
        $refusal  = $attempt->accountRefusal()?->reason;

        if (!$verified instanceof FirstFactor) {
            return $refusal ?? SessionPreconditions::methodReason($driver, $verified);
        }

        if ($refusal !== null || !SessionOwnership::isOwner($session, $verified->identity)) {
            return $refusal ?? FailureReason::INVALID_CREDENTIALS;
        }

        $timebox->returnEarly();

        return $verified;
    }

    /**
     * The session given as stored, read on the write connection, or `null` when
     * its key holds no session of the same generation.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private static function stored(Session $session): (EloquentSession&Model)|null
    {
        $stored = SessionLookup::find($session->getSessionIdentifier());

        return SessionGeneration::isHeld($session, $stored) ? $stored : null;
    }

    /**
     * Whether the locked row is still the session verified, of the same owner
     * and generation.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $verified
     * @return bool
     */
    private static function isSessionVerified(EloquentSession&Model $locked, Identity $identity, EloquentSession&Model $verified): bool
    {
        return SessionOwnership::isOwner($locked, $identity) && SessionGeneration::isSame($locked, $verified);
    }

    /**
     * The id of the challenge the input answers, or `null` for a name no method
     * is registered under.
     *
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function challengeOf(string $method, #[\SensitiveParameter] array $input): ?string
    {
        $methods = $this->container->make(SignInMethodManager::class);

        return in_array($method, $methods->names(), true) ? $methods->method($method)->challenge($input) : null;
    }

    /**
     * Report a refused reauthentication with `AuthenticationFailed`, and answer
     * it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @param  string  $method
     * @param  ?string  $challengeId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     */
    private function fail(Refused $refused, string $method, ?string $challengeId, ClientContext $client): AccessTokenResult
    {
        $session = $refused->session;
        $context = new EventContext($this->context->name(), $client, $refused->identity, $refused->principal, $refused->tenant, $session, $method, fromSession: $session !== null);

        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::REAUTHENTICATION, $refused->reason, null, $refused->retryAfter, $challengeId));

        return AccessTokenResult::failed($refused->reason, $refused->retryAfter);
    }
}
