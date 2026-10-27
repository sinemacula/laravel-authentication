<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Device;

/**
 * A guard's token and session lifetimes, and the deadline arithmetic every
 * token and device follows.
 *
 * An access token lives for the access lifetime. A session (a device) ends at
 * its idle deadline unless a refresh moves that deadline forward, and at its
 * absolute deadline however often it is refreshed: each refresh sets the idle
 * deadline to the idle lifetime from now, never past the absolute deadline,
 * which is fixed when the session starts.
 *
 * All arithmetic is on whole seconds, the precision the deadlines are stored
 * at, and a deadline has passed from the second it names: a session whose
 * deadline is `12:00:00` has ended at `12:00:00`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TokenLifetimes
{
    /** @var int Shortest lifetime of any token or session, in minutes. */
    public const int MIN_TTL_MINUTES = 1;

    /** @var int Longest access token lifetime, in minutes (one day). */
    public const int MAX_ACCESS_TTL_MINUTES = 1440;

    /** @var int Longest idle or absolute session lifetime, in minutes (ten years). */
    public const int MAX_REFRESH_TTL_MINUTES = 5256000;

    /**
     * Constructor.
     *
     * @param  int  $accessTtlMinutes
     * @param  int  $refreshIdleTtlMinutes
     * @param  int  $refreshAbsoluteTtlMinutes
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** How long an access token is valid, in minutes. */
        public int $accessTtlMinutes,

        /** How long a session stays signed in without a refresh, in minutes. */
        public int $refreshIdleTtlMinutes,

        /** How long a session stays signed in however often it is refreshed, in minutes. */
        public int $refreshAbsoluteTtlMinutes,
    ) {
        self::assertWithin('access token lifetime', $accessTtlMinutes, self::MAX_ACCESS_TTL_MINUTES);
        self::assertWithin('idle session lifetime', $refreshIdleTtlMinutes, self::MAX_REFRESH_TTL_MINUTES);
        self::assertWithin('absolute session lifetime', $refreshAbsoluteTtlMinutes, self::MAX_REFRESH_TTL_MINUTES);
    }

    /**
     * Whether a device's session has ended at the given time: either deadline
     * is missing (the device has no session) or has been reached.
     *
     * The one deadline rule, shared by bearer requests, sign-in pins, refresh,
     * and token issuance. Static because it depends on the device's stored
     * deadlines, not on any lifetime setting.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     *
     * @throws \LogicException
     */
    public static function hasEnded(Device $device, CarbonInterface $now): bool
    {
        return self::liveDeadlines($device, $now) === null;
    }

    /**
     * Return a device's idle and absolute deadlines while its session is live
     * at the given time, or `null` once it has ended (see `hasEnded()`). Each
     * deadline is read once.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \Carbon\CarbonInterface  $now
     * @return array{0: \Carbon\CarbonInterface, 1: \Carbon\CarbonInterface}|null
     *
     * @throws \LogicException
     */
    public static function liveDeadlines(Device $device, CarbonInterface $now): ?array
    {
        $idle     = $device->getIdleExpiresAt();
        $absolute = $device->getAbsoluteExpiresAt();

        if ($idle === null || $absolute === null || $now->getTimestamp() >= min($idle->getTimestamp(), $absolute->getTimestamp())) {
            return null;
        }

        return [$idle, $absolute];
    }

    /**
     * The absolute deadline of a session that starts at the given time.
     *
     * @param  \Carbon\CarbonInterface  $signedInAt
     * @return \Carbon\CarbonImmutable
     */
    public function absoluteDeadline(CarbonInterface $signedInAt): CarbonImmutable
    {
        return self::after($signedInAt, $this->refreshAbsoluteTtlMinutes);
    }

    /**
     * The idle deadline a session gets at the given time: the idle lifetime
     * from then, but never past the session's absolute deadline.
     *
     * @param  \Carbon\CarbonInterface  $now
     * @param  \Carbon\CarbonInterface  $absolute
     * @return \Carbon\CarbonImmutable
     */
    public function idleDeadline(CarbonInterface $now, CarbonInterface $absolute): CarbonImmutable
    {
        return self::earliest(self::after($now, $this->refreshIdleTtlMinutes), $absolute);
    }

    /**
     * When an access token issued at the given time expires: the access
     * lifetime from then, but never past the session's absolute deadline when
     * the token belongs to one.
     *
     * @param  \Carbon\CarbonInterface  $issuedAt
     * @param  ?\Carbon\CarbonInterface  $absolute
     * @return \Carbon\CarbonImmutable
     */
    public function accessExpiry(CarbonInterface $issuedAt, ?CarbonInterface $absolute): CarbonImmutable
    {
        $expiry = self::after($issuedAt, $this->accessTtlMinutes);

        return $absolute === null ? $expiry : self::earliest($expiry, $absolute);
    }

    /**
     * The whole second the given number of minutes after a time, in that time's
     * timezone. Counted in elapsed seconds, so a daylight saving change neither
     * stretches nor shortens a lifetime.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @param  int  $minutes
     * @return \Carbon\CarbonImmutable
     */
    private static function after(CarbonInterface $time, int $minutes): CarbonImmutable
    {
        return CarbonImmutable::createFromTimestamp($time->getTimestamp() + ($minutes * 60), $time->getTimezone());
    }

    /**
     * The earlier of a computed deadline and a stored one, on whole seconds and
     * in the computed deadline's timezone.
     *
     * @param  \Carbon\CarbonImmutable  $computed
     * @param  \Carbon\CarbonInterface  $limit
     * @return \Carbon\CarbonImmutable
     */
    private static function earliest(CarbonImmutable $computed, CarbonInterface $limit): CarbonImmutable
    {
        return CarbonImmutable::createFromTimestamp(min($computed->getTimestamp(), $limit->getTimestamp()), $computed->getTimezone());
    }

    /**
     * Reject a lifetime outside its range.
     *
     * @param  string  $lifetime
     * @param  int  $minutes
     * @param  int  $max
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertWithin(string $lifetime, int $minutes, int $max): void
    {
        if ($minutes < self::MIN_TTL_MINUTES || $minutes > $max) {
            throw new \InvalidArgumentException(sprintf('The %s must be from %d to %d minutes, %d given.', $lifetime, self::MIN_TTL_MINUTES, $max, $minutes));
        }
    }
}
