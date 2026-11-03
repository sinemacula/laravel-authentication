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
 * through one of this package's sign-in methods: records a first-factor
 * reauthentication proof on the session and issues it a new access token. It
 * renews the session's authentication time and nothing else: the `amr`, any
 * further factor's standing and the session row are as they were, no refresh
 * token is issued, and nothing is bound.
 *
 * In order: the application policy must allow the method (`method_not_allowed`,
 * nothing counted); the session, read on the write connection, must still be
 * the one given, recording its generation (a session model that reissues keys
 * may have put another session under its key, which is `session_unknown`), and
 * one of this guard's live sessions of a person (the reasons `ProofIssuance`
 * gives);
 * the identifier and the client's IP address must have attempts left under the
 * guard's `sign_in` limits (`rate_limited`, with the wait), counted before any
 * transaction opens; then, inside the guard's credential timebox, the method
 * must verify the input, its account checks counted against the account as a
 * sign-in's are, for the session's own owner: another identity's credential is
 * `invalid_credentials`, never saying whose it was. A concealed reason is
 * answered as `invalid_credentials`. The proof is then recorded and the token
 * issued as `ProofIssuance` describes, the session locked and checked again.
 * The locked row must still be the session that was verified, the same owner's
 * and of the same generation: a session model that reissues a key could
 * otherwise have put another session under it while the credential was checked,
 * which is `session_unknown`, reported for the session verified. Its generation
 * tells even a session of the same owner started in that same second apart, so
 * the proof is never recorded on it and the token, which would carry that
 * session's own further factors and their `mfa`, never issued. The slots are
 * then given back, and `Reauthenticated` reports it once committed. A refusal
 * reports `AuthenticationFailed` (flow `reauthentication`) and is answered,
 * never thrown.
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

        $now    = CarbonImmutable::now()->startOfSecond();
        $policy = CredentialAttempt::checkMethod($this->container, $this->context->name(), $method);

        if ($policy instanceof Refused) {
            return $this->fail($policy, $method, null);
        }

        $challenge = $this->challengeOf($method, $input);
        $outcome   = $this->verified($session, $policy, $method, $input, $now);

        if ($outcome instanceof Refused) {
            return $this->fail($outcome, $method, $challenge);
        }

        [$stored, $factor, $at, $attempt] = $outcome;

        $proof   = new NewProof(ProofKind::FIRST_FACTOR_REAUTHENTICATION, Purpose::REAUTHENTICATE, $method, $factor->channel, null, $factor->observed, null, $factor->methods, $at);
        $accepts = static fn (EloquentSession&Model $row): ?FailureReason => self::isSessionVerified($row, $factor->identity, $stored) ? null : FailureReason::SESSION_UNKNOWN;
        $issued  = $this->issuance->issue($stored->getSessionIdentifier(), $proof, $accepts);

        if ($issued instanceof Refused) {
            $refused = $issued->reason === FailureReason::SESSION_UNKNOWN ? new Refused(FailureReason::SESSION_UNKNOWN, session: $stored) : $issued;

            return $this->fail($refused, $method, $challenge);
        }

        [$admitted, $record, $token, $expires] = $issued;

        $attempt->release();

        $client = $this->context->client();
        $event  = new Reauthenticated(new EventContext($this->context->name(), $client, $admitted->identity, $admitted->principal, $admitted->tenant, $record, $method));

        $this->afterCommit->run($record, fn () => $this->context->dispatch($event));

        return AccessTokenResult::issued($token, $record, $expires);
    }

    /**
     * Check the session, take the attempt's slot, and verify the input for the
     * session's owner under the policy that allowed the method: the stored
     * session, the first factor, the time it was verified and the attempt, or
     * the refusal.
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
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \SineMacula\Laravel\Authentication\Proofs\FirstFactor, 2: \Carbon\CarbonImmutable, 3: \SineMacula\Laravel\Authentication\Sessions\CredentialAttempt}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function verified(Session $session, ApplicationPolicy $policy, string $method, #[\SensitiveParameter] array $input, CarbonImmutable $now): array|Refused
    {
        $guard  = $this->context->name();
        $stored = self::stored($session);
        $live   = $stored === null ? FailureReason::SESSION_UNKNOWN : OwnedSession::refusal($stored, $guard, $now);

        if ($stored === null || $live !== null || SessionOwnership::isMachineOwned($stored)) {
            return new Refused($live ?? FailureReason::MACHINE_IDENTITY, session: $stored);
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
     * The session given as stored, read on the write connection, or `null` when
     * its key holds no session or a session of another generation (or the
     * session given is not an Eloquent session, which records none).
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
     * Whether the locked row is still the session verified: the identity's, and
     * of the generation the verified one records.
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
     * The id of the challenge the input answers, as the method registered under
     * the name says, or `null` for a name no method is registered under. Asked
     * only once the application allowed the method, so a method it does not
     * allow is refused without its driver being built.
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
     * Report a refused reauthentication with `AuthenticationFailed`, with the
     * id of the challenge the input answered, and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @param  string  $method
     * @param  ?string  $challengeId
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     */
    private function fail(Refused $refused, string $method, ?string $challengeId): AccessTokenResult
    {
        $session = $refused->session;
        $client  = $this->context->client();
        $context = new EventContext($this->context->name(), $client, $refused->identity, $refused->principal, $refused->tenant, $session, $method, fromSession: $session !== null);

        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::REAUTHENTICATION, $refused->reason, null, $refused->retryAfter, $challengeId));

        return AccessTokenResult::failed($refused->reason, $refused->retryAfter);
    }
}
