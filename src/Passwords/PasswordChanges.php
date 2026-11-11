<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionGeneration;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;

/**
 * Changes or establishes the password of a signed-in identity from the session
 * it is signed in with, for a guard, ending every other session it has.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasswordChanges
{
    /** @var string What the flow is called in a connection refusal. */
    private const string FLOW = 'A change of password';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionRevocations  $revocations
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the session is of. */
        private GuardContext $context,

        /** Ends every session of the identity but the one the change was made from. */
        private SessionRevocations $revocations,

        /** Container the settings, policies, limiter and hasher are resolved from. */
        private Container $container,
    ) {}

    /**
     * Change the password of the session's owner, with its current password.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $current
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResult
     *
     * @throws \Throwable
     */
    public function change(Session $session, #[\SensitiveParameter] string $current, #[\SensitiveParameter] string $password, ClientContext $client): PasswordResult
    {
        $context = new EventContext($this->context->name(), $client, session: $session);
        $owner   = $this->owner($session);

        if ($owner instanceof FailureReason) {
            return $this->refuse($owner, $context);
        }

        $context = new EventContext($this->context->name(), $context->client, $owner, session: $session);
        $hash    = self::hashOf($owner);
        $proven  = $hash === '' ? FailureReason::PASSWORD_NOT_SET : $this->isCurrentPassword($owner, $current, $context->client->ip);

        if ($proven !== true) {
            return is_int($proven) ? $this->refuse(FailureReason::RATE_LIMITED, $context, $proven) : $this->refuse($proven, $context);
        }

        $stands = static fn (Identity $locked): ?FailureReason => hash_equals($hash, self::hashOf($locked)) ? null : FailureReason::INVALID_CREDENTIALS;

        return $this->write($owner, $session, $password, PasswordFlow::CHANGE, $context, $stands);
    }

    /**
     * Establish a first password for the session's owner, which has none, on
     * the strength of a fresh enough proof on the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResult
     *
     * @throws \Throwable
     */
    public function establish(Session $session, #[\SensitiveParameter] string $password, ClientContext $client): PasswordResult
    {
        $context = new EventContext($this->context->name(), $client, session: $session);
        $owner   = $this->owner($session);

        if ($owner instanceof FailureReason) {
            return $this->refuse($owner, $context);
        }

        $context = new EventContext($this->context->name(), $context->client, $owner, session: $session);

        if (self::hashOf($owner) !== '') {
            return $this->refuse(FailureReason::PASSWORD_ALREADY_SET, $context);
        }

        $freshness = $this->container->make(FreshnessPolicy::class);

        $stands = static fn (Identity $locked, EloquentSession&Model $stored): ?FailureReason => match (true) {
            self::hashOf($locked) !== ''                                                                => FailureReason::PASSWORD_ALREADY_SET,
            $freshness->freshProof($stored, Operations::PASSWORD_ESTABLISHMENT, current: true) === null => FailureReason::REAUTHENTICATION_REQUIRED,
            default                                                                                     => null,
        };

        return $this->write($owner, $session, $password, PasswordFlow::ESTABLISHMENT, $context, $stands);
    }

    /**
     * Judge the new password, then lock the identity's row and the session's,
     * check them again and write the password in one transaction.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession): ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $stands
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResult
     *
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function write(
        Identity&Model $owner,
        Session $session,
        #[\SensitiveParameter] string $password,
        PasswordFlow $flow,
        EventContext $context,
        \Closure $stands,
    ): PasswordResult {
        $check = (new PasswordPolicy($this->container))->check($password);

        if ($check->violations !== []) {
            return PasswordResult::rejected($check->violations);
        }

        // `#[\SensitiveParameter]` does not cover what a closure captures.
        $secret = new \SensitiveParameterValue($password);
        $writer = new PasswordWriter($this->context, $this->revocations, $this->container);
        $client = $context->client;

        try {
            $outcome = $owner->getConnection()->transaction(function () use ($owner, $session, $secret, $flow, $client, $stands, $writer): FailureReason|int {
                $locked = IdentityLock::acquire($owner);
                $stored = SessionLookup::lock($session->getSessionIdentifier());

                if (!$locked instanceof Identity) {
                    return FailureReason::IDENTITY_UNKNOWN;
                }

                if ($stored === null) {
                    return FailureReason::SESSION_UNKNOWN;
                }

                return $this->sessionRefusal($session, $stored, $locked) ?? $stands($locked, $stored) ?? $writer->write($locked, $secret->getValue(), $flow, $client, $stored);
            });
        } catch (PasswordAlreadySet) {
            $outcome = FailureReason::PASSWORD_ALREADY_SET;
        }

        return is_int($outcome) ? PasswordResult::set($outcome) : $this->refuse($outcome, $context);
    }

    /**
     * The session's owner, reloaded through the guard's provider, when the
     * session may change its password; otherwise why not.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function owner(Session $session): FailureReason|(Identity&Model)
    {
        $config = $this->container->make(Repository::class);

        (new PasswordPolicy($this->container))->settings();
        (new CodeKeys($config))->validate();

        $stored  = SessionLookup::find($session->getSessionIdentifier());
        $owner   = $stored === null ? null : $this->reload($stored);
        $refusal = $stored === null ? FailureReason::SESSION_UNKNOWN : $this->sessionRefusal($session, $stored, $owner);

        if ($refusal !== null || $owner === null) {
            return $refusal ?? FailureReason::IDENTITY_UNKNOWN;
        }

        SharedConnection::assert($owner, self::FLOW, $config);

        return $owner;
    }

    /**
     * The session's owner, reloaded through the guard's provider, when it
     * returns an Eloquent identity.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $stored
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null
     */
    private function reload(EloquentSession&Model $stored): (Identity&Model)|null
    {
        $key   = SessionOwnership::ownerKey($stored);
        $owner = $key === null ? null : $this->context->provider()->retrieveById($key);

        return $owner instanceof Identity && $owner instanceof Model ? $owner : null;
    }

    /**
     * Why the session, as stored, may not have its owner's password changed
     * from it, or `null` when it may.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $stored
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private function sessionRefusal(Session $session, EloquentSession&Model $stored, ?Identity $owner): ?FailureReason
    {
        return match (true) {
            !SessionGeneration::isHeld($session, $stored) => FailureReason::SESSION_UNKNOWN,
            SessionOwnership::isMachineOwned($stored)     => FailureReason::MACHINE_IDENTITY,
            default                                       => OwnedSession::refusal($stored, $this->context->name(), CarbonImmutable::now()->startOfSecond())
                ?? ($owner !== null && SessionOwnership::isOwner($stored, $owner) ? null : FailureReason::IDENTITY_UNKNOWN),
        };
    }

    /**
     * Whether the password is the identity's current one, or the seconds until
     * another may be checked, or `invalid_credentials`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $password
     * @param  ?string  $ip
     * @return int|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|true
     *
     * @throws \Throwable
     */
    private function isCurrentPassword(Identity&Model $identity, #[\SensitiveParameter] string $password, ?string $ip): FailureReason|int|true
    {
        $limiter = $this->container->make(AttemptLimiter::class);
        $secret  = new \SensitiveParameterValue($password);

        return $this->context->timebox()->run(function (Timebox $timebox) use ($identity, $secret, $ip, $limiter): FailureReason|int|true {

            $reservation = $limiter->acquire(new AttemptSubject($this->context->name(), AttemptFlow::SIGN_IN, null, null, $ip, AccountAttempts::account($identity)));

            if ($reservation->retryAfter !== null) {
                return $reservation->retryAfter;
            }

            if (!$this->context->provider()->validateCredentials($identity, ['password' => $secret->getValue()])) {
                return FailureReason::INVALID_CREDENTIALS;
            }

            $limiter->release($reservation);
            $timebox->returnEarly();

            return true;
        });
    }

    /**
     * Report a change refused with `AuthenticationFailed`, and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResult
     */
    private function refuse(FailureReason $reason, EventContext $context, ?int $retryAfter = null): PasswordResult
    {
        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::PASSWORD_CHANGE, $reason, retryAfter: $retryAfter));

        return PasswordResult::refused($reason, $retryAfter);
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

        // Eloquent returns the raw attribute, null when no password is set.
        // @phpstan-ignore function.alreadyNarrowedType
        return is_string($hash) ? $hash : '';
    }
}
