<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

/**
 * A guard's token and session lifetimes, and the deadline arithmetic every
 * token and session follows, on whole seconds.
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

    /** @var int Longest refresh grace window, in seconds. */
    public const int MAX_GRACE_SECONDS = 300;

    /**
     * Constructor.
     *
     * @param  int  $accessTtlMinutes
     * @param  int  $refreshIdleTtlMinutes
     * @param  ?int  $refreshAbsoluteTtlMinutes
     * @param  int  $refreshGraceSeconds
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** How long an access token is valid, in minutes. */
        public int $accessTtlMinutes,

        /** How long a session stays signed in without a refresh, in minutes. */
        public int $refreshIdleTtlMinutes,

        /** How long a session stays signed in however often it is refreshed, in minutes; `null` for no absolute limit. */
        public ?int $refreshAbsoluteTtlMinutes,

        /** How long a just-rotated refresh token still gets the current credential, in seconds; 0 disables it. */
        public int $refreshGraceSeconds,
    ) {
        self::assertWithin('access token lifetime', $accessTtlMinutes, self::MIN_TTL_MINUTES, self::MAX_ACCESS_TTL_MINUTES, 'minutes');
        self::assertWithin('idle session lifetime', $refreshIdleTtlMinutes, self::MIN_TTL_MINUTES, self::MAX_REFRESH_TTL_MINUTES, 'minutes');

        if ($refreshAbsoluteTtlMinutes !== null) {
            self::assertWithin('absolute session lifetime', $refreshAbsoluteTtlMinutes, self::MIN_TTL_MINUTES, self::MAX_REFRESH_TTL_MINUTES, 'minutes');
        }

        self::assertWithin('refresh grace window', $refreshGraceSeconds, 0, self::MAX_GRACE_SECONDS, 'seconds');
    }

    /**
     * The absolute deadline of a session that starts at the given time, capped
     * at `$notAfter`; `null` when neither bounds it.
     *
     * @param  \Carbon\CarbonInterface  $signedInAt
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @return ?\Carbon\CarbonImmutable
     */
    public function absoluteDeadline(CarbonInterface $signedInAt, ?CarbonInterface $notAfter = null): ?CarbonImmutable
    {
        $limit = $this->refreshAbsoluteTtlMinutes === null ? null : self::after($signedInAt, $this->refreshAbsoluteTtlMinutes);

        if ($notAfter === null) {
            return $limit;
        }

        $cap = CarbonImmutable::createFromTimestamp($notAfter->getTimestamp(), $signedInAt->getTimezone());

        return $limit === null ? $cap : self::earliest($limit, $cap);
    }

    /**
     * The idle deadline a session gets at the given time, never past its
     * absolute deadline.
     *
     * @param  \Carbon\CarbonInterface  $now
     * @param  ?\Carbon\CarbonInterface  $absolute
     * @return \Carbon\CarbonImmutable
     */
    public function idleDeadline(CarbonInterface $now, ?CarbonInterface $absolute): CarbonImmutable
    {
        $idle = self::after($now, $this->refreshIdleTtlMinutes);

        return $absolute === null ? $idle : self::earliest($idle, $absolute);
    }

    /**
     * The time a token is issued at: the one given, or now, cut to the whole
     * second.
     *
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @return \Carbon\CarbonImmutable
     */
    public static function issueTime(?CarbonInterface $issuedAt): CarbonImmutable
    {
        return ($issuedAt === null ? CarbonImmutable::now() : CarbonImmutable::instance($issuedAt))->startOfSecond();
    }

    /**
     * The latest a token without a session may live until, if anything bounds
     * it: a time that must be after the token's issue time.
     *
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @param  \Carbon\CarbonImmutable  $issuedAt
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    public static function notAfter(?CarbonInterface $notAfter, CarbonImmutable $issuedAt): ?CarbonImmutable
    {
        if ($notAfter !== null && $notAfter->getTimestamp() <= $issuedAt->getTimestamp()) {
            throw new \InvalidArgumentException('Cannot issue a token whose latest expiry is not after its issue time.');
        }

        return $notAfter === null ? null : CarbonImmutable::instance($notAfter);
    }

    /**
     * When an access token issued at the given time expires, never past the end
     * of its session.
     *
     * @param  \Carbon\CarbonInterface  $issuedAt
     * @param  ?\Carbon\CarbonInterface  $sessionEnd
     * @return \Carbon\CarbonImmutable
     */
    public function accessExpiry(CarbonInterface $issuedAt, ?CarbonInterface $sessionEnd): CarbonImmutable
    {
        $expiry = self::after($issuedAt, $this->accessTtlMinutes);

        return $sessionEnd === null ? $expiry : self::earliest($expiry, $sessionEnd);
    }

    /**
     * Whether a refresh token whose rotation id was replaced at `$rotatedAt` is
     * still inside the grace window at `$now`.
     *
     * @param  \Carbon\CarbonInterface  $rotatedAt
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     */
    public function isWithinGrace(CarbonInterface $rotatedAt, CarbonInterface $now): bool
    {
        return $this->refreshGraceSeconds > 0 && $now->getTimestamp() < $rotatedAt->getTimestamp() + $this->refreshGraceSeconds;
    }

    /**
     * The whole second the given number of minutes after a time, in that time's
     * timezone.
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
     * @param  int  $value
     * @param  int  $min
     * @param  int  $max
     * @param  string  $unit
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertWithin(string $lifetime, int $value, int $min, int $max, string $unit): void
    {
        if ($value < $min || $value > $max) {
            throw new \InvalidArgumentException(sprintf('The %s must be from %d to %d %s, %d given.', $lifetime, $min, $max, $unit, $value));
        }
    }
}
