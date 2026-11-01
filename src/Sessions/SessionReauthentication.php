<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;

/**
 * Reauthenticates a session of one guard with its identity's first factor,
 * through one of this package's sign-in methods: records a first-factor
 * reauthentication proof on the session and issues it a new access token. It
 * renews the session's authentication time and nothing else: the `amr`, any
 * further factor's standing and the session row are as they were, no refresh
 * token is issued, and nothing is bound.
 *
 * In order: the application policy must allow the method (`method_not_allowed`,
 * nothing counted); the session, read on the write connection, must be one of
 * this guard's live sessions of a person (the reasons `ProofIssuance` gives);
 * the identifier and the client's IP address must have attempts left under the
 * guard's `sign_in` limits (`rate_limited`, with the wait), counted before any
 * transaction opens; then, inside the guard's credential timebox, the method
 * must verify the input, its account checks counted against the account as a
 * sign-in's are, for the session's own owner: another identity's credential is
 * `invalid_credentials`, never saying whose it was. A concealed reason is
 * answered as `invalid_credentials`. The proof is then recorded and the token
 * issued as `ProofIssuance` describes, the session locked and checked again.
 * The locked row must still be the session that was verified, the same owner's
 * and started at the same second: a session model that reissues a key could
 * otherwise have put another session under it while the credential was checked,
 * which is `session_unknown`, reported for the session verified. A session of
 * the same owner started in that same second is not told apart from it and
 * takes the proof and the token, which that owner's own credential earned. The
 * slots are then given back, and `Reauthenticated` reports it once committed. A
 * refusal reports `AuthenticationFailed` (flow `reauthentication`) and is
 * answered, never thrown.
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
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function reauthenticate(Session $session, string $method, #[\SensitiveParameter] array $input): AccessTokenResult
    {
        SessionPreconditions::assertSessionMethod($method);

        $now     = CarbonImmutable::now()->startOfSecond();
        $outcome = $this->verified($session, $method, $input, $now);

        if ($outcome instanceof Refused) {
            return $this->fail($outcome, $method);
        }

        [$stored, $factor, $at, $attempt] = $outcome;

        $began   = self::signedInAt($stored);
        $proof   = new NewProof(ProofKind::FIRST_FACTOR_REAUTHENTICATION, Purpose::REAUTHENTICATE, $method, $factor->channel, null, $factor->observed, null, $factor->methods, $at);
        $accepts = static fn (EloquentSession&Model $locked): ?FailureReason => self::isSessionVerified($locked, $factor->identity, $began) ? null : FailureReason::SESSION_UNKNOWN;
        $issued  = $this->issuance->issue($stored->getSessionIdentifier(), $proof, $accepts);

        if ($issued instanceof Refused) {
            $refused = $issued->reason === FailureReason::SESSION_UNKNOWN ? new Refused(FailureReason::SESSION_UNKNOWN, session: $stored) : $issued;

            return $this->fail($refused, $method);
        }

        [$admitted, $record, $token, $expires] = $issued;

        $attempt->release();

        $client = $this->context->client();
        $event  = new Reauthenticated(new EventContext($this->context->name(), $client, $admitted->identity, $admitted->principal, $admitted->tenant, $record, $method));

        $this->afterCommit->run($record, fn () => $this->context->dispatch($event));

        return AccessTokenResult::issued($token, $record, $expires);
    }

    /**
     * Check the method and the session, take the attempt's slot, and verify the
     * input for the session's owner: the stored session, the first factor, the
     * time it was verified and the attempt, or the refusal.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \SineMacula\Laravel\Authentication\Proofs\FirstFactor, 2: \Carbon\CarbonImmutable, 3: \SineMacula\Laravel\Authentication\Sessions\CredentialAttempt}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function verified(Session $session, string $method, #[\SensitiveParameter] array $input, CarbonImmutable $now): array|Refused
    {
        $guard  = $this->context->name();
        $policy = CredentialAttempt::checkMethod($this->container, $guard, $method);
        $stored = $policy instanceof Refused ? null : SessionLookup::find($session->getSessionIdentifier());
        $live   = $stored === null ? FailureReason::SESSION_UNKNOWN : OwnedSession::refusal($stored, $guard, $now);

        if ($policy instanceof Refused || $stored === null || $live !== null || SessionOwnership::isMachineOwned($stored)) {
            return match (true) {
                $policy instanceof Refused => $policy,
                $live !== null             => new Refused($live, session: $stored),
                default                    => new Refused(FailureReason::MACHINE_IDENTITY, session: $stored),
            };
        }

        $driver  = $this->container->make(SignInMethodManager::class)->method($method);
        $subject = new AttemptSubject($guard, AttemptFlow::SIGN_IN, $driver->identifier($guard, $input), $driver->identifierType($guard), $this->context->client()->ip);
        $attempt = CredentialAttempt::begin($this->container->make(AttemptLimiter::class), $policy, $subject);

        if ($attempt instanceof Refused) {
            return new Refused($attempt->reason, session: $stored, retryAfter: $attempt->retryAfter);
        }

        $request = new SignInRequest($guard, $this->context->provider(), $input, $this->context->client(), $attempt->accounts->reserve(...));

        $factor = $this->context->timebox()->run(fn (Timebox $timebox): FailureReason|FirstFactor => $this->verify($driver, $request, $attempt, $stored, $timebox));

        return $factor instanceof FirstFactor
            ? [$stored, $factor, CarbonImmutable::now()->startOfSecond(), $attempt]
            : new Refused($factor, session: $stored, retryAfter: $attempt->accountRefusal()?->retryAfter);
    }

    /**
     * Verify the input with the method, for the session's owner, cutting the
     * timebox short only when it verified: the first factor, or why not.
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
     * Whether the locked row is still the session verified: the identity's, and
     * started at the second the verified one started.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $locked
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?int  $began
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isSessionVerified(EloquentSession&Model $locked, Identity $identity, ?int $began): bool
    {
        return SessionOwnership::isOwner($locked, $identity) && self::signedInAt($locked) === $began;
    }

    /**
     * When the session started, to the second, read on the write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?int
     *
     * @throws \LogicException
     */
    private static function signedInAt(EloquentSession&Model $session): ?int
    {
        return WriteConnection::during($session, static fn (): ?int => $session->getSignedInAt()?->getTimestamp());
    }

    /**
     * Report a refused reauthentication with `AuthenticationFailed` and answer
     * it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @param  string  $method
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     */
    private function fail(Refused $refused, string $method): AccessTokenResult
    {
        $session = $refused->session;
        $client  = $this->context->client();
        $context = new EventContext($this->context->name(), $client, $refused->identity, $refused->principal, $refused->tenant, $session, $method, fromSession: $session !== null);

        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::REAUTHENTICATION, $refused->reason, null, $refused->retryAfter));

        return AccessTokenResult::failed($refused->reason, $refused->retryAfter);
    }
}
