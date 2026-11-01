<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionGeneration;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * Decides whether a `Reauthentication` proves that an identity authenticated
 * recently enough, through a guard, for a change of its identifiers: the
 * freshness policy's `identifier_change` operation decides how recently, and by
 * which proofs.
 *
 * A session proof is read again by its key on the write connection, so the
 * instance the caller holds cannot stand in for the stored row; it must still
 * be that session (of its generation, so another session a model put under the
 * key is not), the identity's own (its recorded owner), of the guard, not
 * revoked and not ended, and the freshness policy must find one of its proofs
 * that meets the operation's requirement (see `FreshnessPolicy`: a proof of a
 * kind the requirement takes, made within its age). A password proof is a
 * reauthentication with the first factor made now, so it is accepted only when
 * that requirement takes `first_factor_reauthentication` and asks for neither
 * multifactor authentication nor phishing resistance, which a password never
 * shows, and only on a guard whose application allows the password method. It
 * is checked inside the guard's credential timebox, against the identity read
 * again through the guard's identity provider on the write connection (it must
 * still be the same row), and counted first against the identity's account and
 * the IP address under the guard's `sign_in` limits, as a sign-in's password
 * is; a correct one gives its slot back.
 *
 * `refusal()` counts a password's attempt, so it runs before the transaction
 * that acts on the proof: inside it, the counters' rows would stay locked until
 * the commit, and MySQL deadlocks two transactions that each create a counter
 * in the same gap of the index. `stands()` then checks the accepted proof again
 * inside that transaction, once the identity's row is locked, without counting:
 * the session is read again with its row locked until the transaction ends and
 * judged as locked, and the freshness policy asked within it, so a revocation
 * cannot fall between the check and what the proof allows, and a password
 * stands while the locked row holds the hash it was checked against.
 *
 * Made for one check and dropped with it; it keeps nothing between calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecentAuthentication
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the identity authenticated through. */
        private GuardContext $context,

        /** Container the freshness policy, the application policy and the attempt limiter are resolved from. */
        private Container $container,
    ) {}

    /**
     * Why the proof does not show that the identity authenticated recently
     * enough, from the IP address given: `reauthentication_required`, or the
     * seconds until a password may be checked again when its limits refused
     * it; `null` when it does.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  ?string  $ip
     * @return int|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function refusal(Identity $identity, Reauthentication $proof, ?string $ip): FailureReason|int|null
    {
        $proven = $proof->apply(
            fn (Session $session): bool => $this->isFreshSession($identity, $session, SessionLookup::find($session->getSessionIdentifier())),
            fn (#[\SensitiveParameter] string $password): bool|int => $this->isCurrentPassword($identity, $password, $ip),
        );

        return match ($proven) {
            true    => null,
            false   => FailureReason::REAUTHENTICATION_REQUIRED,
            default => $proven,
        };
    }

    /**
     * Whether a proof `refusal()` accepted still stands, inside the transaction
     * that acts on it and once the identity's row is locked: a session proof is
     * checked again, its row locked and the freshness policy asked inside the
     * transaction; a password proof stands while the locked row's password hash
     * is the one the row held when it was read before the password was checked
     * (a hash is salted afresh on every write, so any password written in
     * between changes it).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $before
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $locked
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function stands(Identity $before, Identity $locked, Reauthentication $proof): bool
    {
        return $proof->apply(
            fn (Session $session): bool => $this->isFreshSession($locked, $session, SessionLookup::lock($session->getSessionIdentifier())),
            static fn (): bool => hash_equals(self::hashOf($before), self::hashOf($locked)),
        );
    }

    /**
     * Whether the session, as stored, is still the session given (of its
     * generation: a session model that reissues keys may have put another
     * session under its key, the identity's own included), one of the
     * identity's live sessions of this guard, and has a proof fresh enough for
     * an identifier change.
     *
     * The row given is judged here, not only by the freshness policy, which
     * reads the session again with no lock of its own: in `stands()` it is the
     * locked row, which a revocation committed in the meantime has reached even
     * where the transaction reads an earlier snapshot without a lock (MySQL's
     * REPEATABLE READ), and a rebound policy is never trusted to check it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $stored
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function isFreshSession(Identity $identity, Session $session, (EloquentSession&Model)|null $stored): bool
    {
        return SessionGeneration::isHeld($session, $stored)
            && SessionOwnership::isOwner($stored, $identity)
            && OwnedSession::refusal($stored, $this->context->name(), CarbonImmutable::now()->startOfSecond()) === null
            && $this->container->make(FreshnessPolicy::class)->freshProof($stored, Operations::IDENTIFIER_CHANGE) !== null;
    }

    /**
     * Whether the password is the identity's current one, checked inside the
     * guard's credential timebox once a slot of the account's and the IP
     * address's sign-in limits is taken; the seconds until another may be
     * checked when they had none. A guard whose freshness for identifier
     * changes does not take a password, or whose application does not allow the
     * password method, accepts no password as proof, and counts nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $password
     * @param  ?string  $ip
     * @return bool|int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function isCurrentPassword(Identity $identity, #[\SensitiveParameter] string $password, ?string $ip): bool|int
    {
        if (!$this->takesPassword() || !$this->container->make(ApplicationPolicy::class)->allowsMethod($this->context->name(), PasswordSignIn::NAME)) {
            return false;
        }

        $limiter = $this->container->make(AttemptLimiter::class);

        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $secret = new \SensitiveParameterValue($password);

        return $this->context->timebox()->run(function (Timebox $timebox) use ($identity, $secret, $ip, $limiter): bool|int {

            $reservation = $limiter->acquire(new AttemptSubject($this->context->name(), AttemptFlow::SIGN_IN, null, null, $ip, AccountAttempts::account($identity)));

            if ($reservation->retryAfter !== null) {
                return $reservation->retryAfter;
            }

            $provider = $this->context->provider();
            $stored   = $provider->retrieveById($identity->getAuthIdentifier());

            $isSameRow = $stored instanceof Identity && AccountAttempts::account($stored) === AccountAttempts::account($identity);

            if (!$isSameRow || !$provider->validateCredentials($stored, ['password' => $secret->getValue()])) {
                return false;
            }

            $limiter->release($reservation);
            $timebox->returnEarly();

            return true;
        });
    }

    /**
     * The identity's password hash, read on the write connection, or an empty
     * string when it has none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return string
     */
    private static function hashOf(Identity $identity): string
    {
        $hash = WriteConnection::during($identity, static fn (): mixed => $identity->getAuthPassword());

        // The contract documents a string, but Eloquent returns the raw
        // attribute: null for an account stored without a password.
        // @phpstan-ignore function.alreadyNarrowedType
        return is_string($hash) ? $hash : '';
    }

    /**
     * Whether the freshness the guard requires for an identifier change takes a
     * password checked now: a first-factor reauthentication, with neither
     * multifactor authentication nor phishing resistance asked for.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function takesPassword(): bool
    {
        $requirement = $this->container->make(FreshnessPolicy::class)->requirement($this->context->name(), Operations::IDENTIFIER_CHANGE);

        return $requirement !== null
            && $requirement->takes(ProofKind::FIRST_FACTOR_REAUTHENTICATION)
            && !$requirement->multifactor
            && !$requirement->phishingResistant;
    }
}
