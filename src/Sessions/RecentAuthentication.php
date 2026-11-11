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
 * Decides whether a `Reauthentication` proves an identity authenticated
 * recently enough, through a guard, for a change of its identifiers.
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
     * Why the proof does not show the identity authenticated recently enough,
     * or `null` when it does.
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
            fn (Session $session): bool => $this->isFreshSession($identity, $session, SessionLookup::find($session->getSessionIdentifier()), false),
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
     * that acts on it and once the identity's row is locked.
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
            fn (Session $session): bool => $this->isFreshSession($locked, $session, SessionLookup::lock($session->getSessionIdentifier()), true),
            static fn (): bool => hash_equals(self::hashOf($before), self::hashOf($locked)),
        );
    }

    /**
     * Whether the session, as stored, is still the one given, a live session of
     * the identity on this guard, and has a proof fresh enough for an
     * identifier change.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $stored
     * @param  bool  $locked
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function isFreshSession(Identity $identity, Session $session, (EloquentSession&Model)|null $stored, bool $locked): bool
    {
        return SessionGeneration::isHeld($session, $stored)
            && SessionOwnership::isOwner($stored, $identity)
            && OwnedSession::refusal($stored, $this->context->name(), CarbonImmutable::now()->startOfSecond()) === null
            && $this->container->make(FreshnessPolicy::class)->freshProof($stored, Operations::IDENTIFIER_CHANGE, current: $locked) !== null;
    }

    /**
     * Whether the password is the identity's current one, once a slot of its
     * sign-in limits is taken; the seconds until another may be checked when
     * none was free.
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
     * password checked now.
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
