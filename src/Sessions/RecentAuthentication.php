<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Devices\DeviceLookup;
use SineMacula\Laravel\Authentication\Devices\DeviceOwnership;
use SineMacula\Laravel\Authentication\Devices\OwnedDevice;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * Decides whether a `Reauthentication` proves that an identity authenticated
 * recently enough, within a window of seconds, through a guard.
 *
 * A time is within the window from the second it names until, and not
 * including, the second the window after it: a time in the future proves
 * nothing. A device proof is read again by its key on the write connection, so
 * the instance the caller holds cannot stand in for the stored row; it must be
 * the identity's own (its recorded owner), of the guard, not revoked, with its
 * session not ended, and signed in within the window. A password proof is
 * accepted only on a guard whose audience allows the password method (one that
 * signs in only by code or passkey takes none); it is checked inside the
 * guard's credential timebox, against the identity read again through the
 * guard's identity provider on the write connection (it must still be the same
 * row), and counted first against the identity's account and the IP address
 * under the guard's `sign_in` limits, as a sign-in's password is; a correct one
 * gives its slot back. A confirmation time is trusted as given.
 *
 * `refusal()` counts a password's attempt, so it runs before the transaction
 * that acts on the proof: inside it, the counters' rows would stay locked until
 * the commit, and MySQL deadlocks two transactions that each create a counter
 * in the same gap of the index. `stands()` then checks the accepted proof again
 * inside that transaction, once the identity's row is locked, without counting:
 * the device is read again with its row locked until the transaction ends, so a
 * revocation cannot fall between the check and what the proof allows, and a
 * password stands while the locked row holds the hash it was checked against.
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
     * @param  int  $window
     * @param  \Carbon\CarbonImmutable  $now
     */
    public function __construct(

        /** The context of the guard the identity authenticated through. */
        private GuardContext $context,

        /** Container the attempt limiter is resolved from. */
        private Container $container,

        /** How recently the identity must have authenticated, in seconds. */
        private int $window,

        /** The time the check is made at. */
        private CarbonImmutable $now,
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     */
    public function refusal(Identity $identity, Reauthentication $proof, ?string $ip): FailureReason|int|null
    {
        $proven = $proof->apply(
            fn (Device $device): bool => $this->isRecentDevice($identity, DeviceLookup::find($device->getDeviceIdentifier())),
            fn (#[\SensitiveParameter] string $password): bool|int => $this->isCurrentPassword($identity, $password, $ip),
            fn (CarbonImmutable $at): bool => $this->isRecent($at),
        );

        return match ($proven) {
            true    => null,
            false   => FailureReason::REAUTHENTICATION_REQUIRED,
            default => $proven,
        };
    }

    /**
     * Whether a proof `refusal()` accepted still stands, inside the transaction
     * that acts on it and once the identity's row is locked: a device proof is
     * checked again, its row locked; a password proof stands while the locked
     * row's password hash is the one the row held when it was read before the
     * password was checked (a hash is salted afresh on every write, so any
     * password written in between changes it); a confirmation time does.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $before
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $locked
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function stands(Identity $before, Identity $locked, Reauthentication $proof): bool
    {
        return $proof->apply(
            fn (Device $device): bool => $this->isRecentDevice($locked, DeviceLookup::lock($device->getDeviceIdentifier())),
            static fn (): bool => hash_equals(self::hashOf($before), self::hashOf($locked)),
            static fn (): bool => true,
        );
    }

    /**
     * Whether the device, as stored, is one of the identity's live sessions of
     * the guard and signed in within the window.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null  $stored
     * @return bool
     *
     * @throws \LogicException
     */
    private function isRecentDevice(Identity $identity, (EloquentDevice&Model)|null $stored): bool
    {
        return $stored !== null
            && DeviceOwnership::isOwner($stored, $identity)
            && OwnedDevice::refusal($stored, $this->context->name(), $this->now) === null
            && $this->isRecent(WriteConnection::during($stored, static fn (): ?CarbonInterface => $stored->getSignedInAt()));
    }

    /**
     * Whether the password is the identity's current one, checked inside the
     * guard's credential timebox once a slot of the account's and the IP
     * address's sign-in limits is taken; the seconds until another may be
     * checked when they had none. A guard whose audience does not allow the
     * password method accepts no password as proof, and counts nothing.
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
        if (!$this->container->make(AudiencePolicy::class)->allowsMethod($this->context->name(), PasswordSignIn::NAME)) {
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
     * Whether the time is within the window: not in the future, and less than
     * the window ago.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return bool
     */
    private function isRecent(?CarbonInterface $at): bool
    {
        return $at !== null && $at->getTimestamp() <= $this->now->getTimestamp() && $this->now->getTimestamp() < $at->getTimestamp() + $this->window;
    }
}
