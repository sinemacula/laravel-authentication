<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Guards\OwnedDevice;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;
use SineMacula\Laravel\Authentication\Jwt\DeviceOwnership;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * Decides whether a `Reauthentication` proves that an identity authenticated
 * recently enough, within a window of seconds, through a guard.
 *
 * A time is within the window from the second it names until, and not
 * including, the second the window after it: a time in the future proves
 * nothing. A device proof is read again by its key on the write connection, so
 * the instance the caller holds cannot stand in for the stored row, and must be
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
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  int  $window
     * @param  \Carbon\CarbonImmutable  $now
     */
    public function __construct(

        /** The guard the identity authenticated through. */
        private JwtGuard $guard,

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
     */
    public function refusal(Identity $identity, Reauthentication $proof, ?string $ip): FailureReason|int|null
    {
        $proven = $proof->apply(
            fn (Device $device): bool => $this->isRecentDevice($identity, $device),
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
     * Whether the device, as stored, is one of the identity's live sessions of
     * the guard and signed in within the window.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function isRecentDevice(Identity $identity, Device $device): bool
    {
        $stored = DeviceLookup::find($device->getDeviceIdentifier());

        return $stored !== null
            && DeviceOwnership::isOwner($stored, $identity)
            && OwnedDevice::refusal($stored, $this->guard->getName(), $this->now) === null
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
     */
    private function isCurrentPassword(Identity $identity, #[\SensitiveParameter] string $password, ?string $ip): bool|int
    {
        if (!$this->container->make(AudiencePolicy::class)->allowsMethod($this->guard->getName(), PasswordSignIn::NAME)) {
            return false;
        }

        $limiter = $this->container->make(AttemptLimiter::class);

        return $this->guard->timeboxed(function (Timebox $timebox) use ($identity, $password, $ip, $limiter): bool|int {

            $reservation = $limiter->acquire(new AttemptSubject($this->guard->getName(), AttemptFlow::SIGN_IN, null, null, $ip, AccountAttempts::account($identity)));

            if ($reservation->retryAfter !== null) {
                return $reservation->retryAfter;
            }

            $provider = $this->guard->getProvider();
            $stored   = $provider->retrieveById($identity->getAuthIdentifier());

            $isSameRow = $stored instanceof Identity && AccountAttempts::account($stored) === AccountAttempts::account($identity);

            if (!$isSameRow || !$provider->validateCredentials($stored, ['password' => $password])) {
                return false;
            }

            $limiter->release($reservation);
            $timebox->returnEarly();

            return true;
        });
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
