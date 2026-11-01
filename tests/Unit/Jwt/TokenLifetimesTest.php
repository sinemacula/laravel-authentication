<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Unit tests for the token and session lifetime arithmetic.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenLifetimes::class)]
final class TokenLifetimesTest extends TestCase
{
    /** @var int Access token lifetime used by the tests, in minutes. */
    private const int ACCESS = 5;

    /** @var int Idle session lifetime used by the tests, in minutes. */
    private const int IDLE = 60;

    /** @var int Absolute session lifetime used by the tests, in minutes. */
    private const int ABSOLUTE = 600;

    /** @var \Carbon\CarbonImmutable Reference time, with a fraction of a second. */
    private CarbonImmutable $now;

    /**
     * Build the reference time.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::parse('2026-04-06 12:00:00.750000', 'Europe/London');
    }

    /**
     * The lifetimes are exposed as given.
     *
     * @return void
     */
    public function testExposesTheLifetimes(): void
    {
        $lifetimes = new TokenLifetimes(self::ACCESS, self::IDLE, self::ABSOLUTE, 30);

        self::assertSame(self::ACCESS, $lifetimes->accessTtlMinutes);
        self::assertSame(self::IDLE, $lifetimes->refreshIdleTtlMinutes);
        self::assertSame(self::ABSOLUTE, $lifetimes->refreshAbsoluteTtlMinutes);
        self::assertSame(30, $lifetimes->refreshGraceSeconds);
    }

    /**
     * Rows of `[access, idle, absolute, grace, accepted]` at and beyond each
     * range bound; an absolute lifetime of `null` is none, and accepted.
     *
     * @return iterable<string, array{0: int, 1: int, 2: ?int, 3: int, 4: bool}>
     */
    public static function provideLifetimeBounds(): iterable
    {
        yield from [
            'all at the minimum'         => [1, 1, 1, 0, true],
            'all at the maximum'         => [1440, 5256000, 5256000, 300, true],
            'access below the minimum'   => [0, 1, 1, 0, false],
            'access above the maximum'   => [1441, 1, 1, 0, false],
            'idle below the minimum'     => [1, 0, 1, 0, false],
            'idle above the maximum'     => [1, 5256001, 1, 0, false],
            'absolute below the minimum' => [1, 1, 0, 0, false],
            'absolute above the maximum' => [1, 1, 5256001, 0, false],
            'no absolute lifetime'       => [1, 1, null, 0, true],
            'grace below the minimum'    => [1, 1, 1, -1, false],
            'grace above the maximum'    => [1, 1, 1, 301, false],
            'negative'                   => [-5, 1, 1, 0, false],
        ];
    }

    /**
     * Each lifetime must lie within its range, so a hand-built instance can
     * hold neither a zero lifetime nor one long enough to overflow a stored
     * timestamp, and the grace window stays short.
     *
     * @param  int  $access
     * @param  int  $idle
     * @param  ?int  $absolute
     * @param  int  $grace
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideLifetimeBounds')]
    public function testRejectsALifetimeOutsideItsRange(int $access, int $idle, ?int $absolute, int $grace, bool $accepted): void
    {
        if (!$accepted) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessageMatches(
                '/^The (access token lifetime|idle session lifetime|absolute session lifetime|refresh grace window)'
                . ' must be from (0|1) to (300|1440|5256000) (minutes|seconds), -?\d+ given\.$/',
            );
        }

        $lifetimes = new TokenLifetimes($access, $idle, $absolute, $grace);

        self::assertSame($grace, $lifetimes->refreshGraceSeconds);
    }

    /**
     * The absolute deadline is the absolute lifetime after the sign-in, cut to
     * the whole second and kept in the sign-in's timezone.
     *
     * @return void
     */
    public function testAbsoluteDeadlineIsTheAbsoluteLifetimeAfterSignIn(): void
    {
        $deadline = $this->lifetimes()->absoluteDeadline($this->now);

        self::assertNotNull($deadline);
        self::assertSame('2026-04-06 22:00:00.000000', $deadline->format('Y-m-d H:i:s.u'));
        self::assertSame('Europe/London', $deadline->getTimezone()->getName());
    }

    /**
     * Without an absolute lifetime a session has no absolute deadline unless
     * its sign-in supplied one.
     *
     * @return void
     */
    public function testNoAbsoluteLifetimeMeansNoAbsoluteDeadline(): void
    {
        $lifetimes = new TokenLifetimes(self::ACCESS, self::IDLE, null, 30);

        self::assertNull($lifetimes->refreshAbsoluteTtlMinutes);
        self::assertNull($lifetimes->absoluteDeadline($this->now));
        self::assertNull($lifetimes->absoluteDeadline($this->now, null));
    }

    /**
     * Rows of `[absolute lifetime or null, seconds from now to the sign-in's
     * deadline or null, seconds from now to the expected absolute deadline or
     * null]`.
     *
     * @return iterable<string, array{0: ?int, 1: ?int, 2: ?int}>
     */
    public static function provideAbsoluteCaps(): iterable
    {
        yield from [
            'lifetime alone'                   => [self::ABSOLUTE, null, 36000],
            'deadline alone'                   => [null, 120, 120],
            'deadline before the lifetime'     => [self::ABSOLUTE, 35999, 35999],
            'deadline at the lifetime'         => [self::ABSOLUTE, 36000, 36000],
            'deadline after the lifetime'      => [self::ABSOLUTE, 36001, 36000],
            'deadline well after the lifetime' => [self::ABSOLUTE, 86400, 36000],
            'neither'                          => [null, null, null],
        ];
    }

    /**
     * The absolute deadline is the earlier of the absolute lifetime from the
     * sign-in and the deadline the sign-in supplied, either alone when the
     * other is absent, on whole seconds and in the sign-in's timezone.
     *
     * @param  ?int  $absolute
     * @param  ?int  $notAfterIn
     * @param  ?int  $expectedIn
     * @return void
     */
    #[DataProvider('provideAbsoluteCaps')]
    public function testAbsoluteDeadlineIsTheEarlierOfTheLifetimeAndTheSignInsDeadline(?int $absolute, ?int $notAfterIn, ?int $expectedIn): void
    {
        $now      = $this->now->startOfSecond();
        $notAfter = $notAfterIn === null ? null : $this->now->utc()->addSeconds($notAfterIn);
        $deadline = (new TokenLifetimes(self::ACCESS, self::IDLE, $absolute, 30))->absoluteDeadline($this->now, $notAfter);

        self::assertSame($expectedIn === null ? null : $now->getTimestamp() + $expectedIn, $deadline?->getTimestamp());
        self::assertSame($expectedIn === null ? null : 'Europe/London', $deadline?->getTimezone()->getName());
        self::assertSame($expectedIn === null ? null : 0, $deadline?->microsecond);
    }

    /**
     * Lifetimes count elapsed time, so one that crosses a daylight saving
     * change is neither stretched nor shortened by it.
     *
     * @return void
     */
    public function testDeadlinesCountElapsedTimeAcrossDaylightSavingChanges(): void
    {
        $beforeChange = CarbonImmutable::parse('2026-03-29 00:30:00', 'Europe/London');

        $deadline = $this->lifetimes()->absoluteDeadline($beforeChange);

        self::assertNotNull($deadline);
        self::assertSame(self::ABSOLUTE * 60, $deadline->getTimestamp() - $beforeChange->getTimestamp());
    }

    /**
     * Rows of `[seconds from now to the absolute deadline, seconds from now to
     * the expected idle deadline]` either side of the idle lifetime.
     *
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function provideIdleCaps(): iterable
    {
        yield from [
            'absolute well after the idle lifetime'  => [36000, 3600],
            'absolute one second after'              => [3601, 3600],
            'absolute exactly at the idle lifetime'  => [3600, 3600],
            'absolute one second before'             => [3599, 3599],
            'absolute well before the idle lifetime' => [60, 60],
        ];
    }

    /**
     * The idle deadline is the idle lifetime from now, but never past the
     * absolute deadline.
     *
     * @param  int  $absoluteIn
     * @param  int  $expectedIn
     * @return void
     */
    #[DataProvider('provideIdleCaps')]
    public function testIdleDeadlineIsCappedAtTheAbsoluteDeadline(int $absoluteIn, int $expectedIn): void
    {
        $now      = $this->now->startOfSecond();
        $deadline = $this->lifetimes()->idleDeadline($this->now, $now->addSeconds($absoluteIn));

        self::assertSame($now->getTimestamp() + $expectedIn, $deadline->getTimestamp());
        self::assertSame(0, $deadline->microsecond);
    }

    /**
     * Without an absolute deadline the idle deadline is the idle lifetime from
     * now, uncapped, on whole seconds and in now's timezone.
     *
     * @return void
     */
    public function testIdleDeadlineIsUncappedWithoutAnAbsoluteDeadline(): void
    {
        $deadline = $this->lifetimes()->idleDeadline($this->now, null);

        self::assertSame($this->now->startOfSecond()->getTimestamp() + (self::IDLE * 60), $deadline->getTimestamp());
        self::assertSame(0, $deadline->microsecond);
        self::assertSame('Europe/London', $deadline->getTimezone()->getName());
    }

    /**
     * Rows of `[seconds from now to the end of the session or null, seconds
     * from now to the expected access expiry]`.
     *
     * @return iterable<string, array{0: ?int, 1: int}>
     */
    public static function provideAccessCaps(): iterable
    {
        yield from [
            'no session'                       => [null, 300],
            'session ends after the lifetime'  => [301, 300],
            'session ends at the lifetime'     => [300, 300],
            'session ends before the lifetime' => [299, 299],
        ];
    }

    /**
     * An access token expires after the access lifetime, and never after the
     * end of its session.
     *
     * @param  ?int  $sessionEndsIn
     * @param  int  $expectedIn
     * @return void
     */
    #[DataProvider('provideAccessCaps')]
    public function testAccessExpiryIsCappedAtTheSessionEnd(?int $sessionEndsIn, int $expectedIn): void
    {
        $now    = $this->now->startOfSecond();
        $expiry = $this->lifetimes()->accessExpiry($this->now, $sessionEndsIn === null ? null : $now->addSeconds($sessionEndsIn));

        self::assertSame($now->getTimestamp() + $expectedIn, $expiry->getTimestamp());
    }

    /**
     * A replaced rotation id is inside the grace window up to, but not
     * including, the second the window ends.
     *
     * @return void
     */
    public function testGraceWindowEndsAtItsLastSecond(): void
    {
        $lifetimes = $this->lifetimes();
        $rotatedAt = $this->now->startOfSecond();

        self::assertTrue($lifetimes->isWithinGrace($rotatedAt, $rotatedAt));
        self::assertTrue($lifetimes->isWithinGrace($rotatedAt, $rotatedAt->addSeconds(29)->addMilliseconds(999)));
        self::assertFalse($lifetimes->isWithinGrace($rotatedAt, $rotatedAt->addSeconds(30)));
        self::assertFalse($lifetimes->isWithinGrace($rotatedAt, $rotatedAt->addSeconds(31)));
    }

    /**
     * A grace window of 0 never applies, not even to a rotation stamped later
     * than now by a server whose clock runs ahead.
     *
     * @return void
     */
    public function testZeroGraceWindowNeverApplies(): void
    {
        $lifetimes = new TokenLifetimes(self::ACCESS, self::IDLE, self::ABSOLUTE, 0);
        $rotatedAt = $this->now->startOfSecond();

        self::assertFalse($lifetimes->isWithinGrace($rotatedAt, $rotatedAt));
        self::assertFalse($lifetimes->isWithinGrace($rotatedAt->addSeconds(10), $rotatedAt));
    }

    /**
     * A rotation stamped later than now by a server whose clock runs ahead is
     * still inside a non-zero window: the window counts from the stamp.
     *
     * @return void
     */
    public function testGraceWindowCountsFromAStampAheadOfNow(): void
    {
        $rotatedAt = $this->now->startOfSecond();

        self::assertTrue($this->lifetimes()->isWithinGrace($rotatedAt->addSeconds(10), $rotatedAt));
    }

    /**
     * Build lifetimes of 5 minutes access, 1 hour idle, and 10 hours absolute.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    private function lifetimes(): TokenLifetimes
    {
        return new TokenLifetimes(self::ACCESS, self::IDLE, self::ABSOLUTE, 30);
    }
}
