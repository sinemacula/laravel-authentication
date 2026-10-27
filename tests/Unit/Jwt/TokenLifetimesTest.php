<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
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
    use MockeryPHPUnitIntegration;

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
     * range bound.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int, 3: int, 4: bool}>
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
     * @param  int  $absolute
     * @param  int  $grace
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideLifetimeBounds')]
    public function testRejectsALifetimeOutsideItsRange(int $access, int $idle, int $absolute, int $grace, bool $accepted): void
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

        self::assertSame('2026-04-06 22:00:00.000000', $deadline->format('Y-m-d H:i:s.u'));
        self::assertSame('Europe/London', $deadline->getTimezone()->getName());
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
     * Rows of `[seconds from now to the absolute deadline or null, seconds from
     * now to the expected access expiry]`.
     *
     * @return iterable<string, array{0: ?int, 1: int}>
     */
    public static function provideAccessCaps(): iterable
    {
        yield from [
            'no device'                    => [null, 300],
            'absolute after the lifetime'  => [301, 300],
            'absolute at the lifetime'     => [300, 300],
            'absolute before the lifetime' => [299, 299],
        ];
    }

    /**
     * An access token expires after the access lifetime, and never after the
     * absolute deadline of its device's session.
     *
     * @param  ?int  $absoluteIn
     * @param  int  $expectedIn
     * @return void
     */
    #[DataProvider('provideAccessCaps')]
    public function testAccessExpiryIsCappedAtTheAbsoluteDeadline(?int $absoluteIn, int $expectedIn): void
    {
        $now    = $this->now->startOfSecond();
        $expiry = $this->lifetimes()->accessExpiry($this->now, $absoluteIn === null ? null : $now->addSeconds($absoluteIn));

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
     * Rows of `[seconds from now to the idle deadline or null, seconds from
     * now to the absolute deadline or null, whether the session has ended]`.
     *
     * @return iterable<string, array{0: ?int, 1: ?int, 2: bool}>
     */
    public static function provideSessions(): iterable
    {
        yield from [
            'both ahead'                   => [60, 120, false],
            'idle one second ahead'        => [1, 120, false],
            'idle reached this second'     => [0, 120, true],
            'idle passed'                  => [-1, 120, true],
            'absolute one second ahead'    => [60, 1, false],
            'absolute reached this second' => [60, 0, true],
            'absolute passed'              => [60, -1, true],
            'no idle deadline'             => [null, 120, true],
            'no absolute deadline'         => [60, null, true],
            'no deadlines'                 => [null, null, true],
        ];
    }

    /**
     * A session has ended from the second either deadline names, or when it has
     * no deadline at all; fractions of a second do not count.
     *
     * @param  ?int  $idleIn
     * @param  ?int  $absoluteIn
     * @param  bool  $ended
     * @return void
     */
    #[DataProvider('provideSessions')]
    public function testHasEndedAtEitherDeadlineOrWithoutOne(?int $idleIn, ?int $absoluteIn, bool $ended): void
    {
        $now    = $this->now->startOfSecond();
        $device = $this->device($idleIn === null ? null : $now->addSeconds($idleIn), $absoluteIn === null ? null : $now->addSeconds($absoluteIn), 2);

        self::assertSame($ended, TokenLifetimes::hasEnded($device, $this->now));
        self::assertSame($ended, TokenLifetimes::liveDeadlines($device, $this->now) === null);
    }

    /**
     * A live session's deadlines are returned as the device reported them.
     *
     * @return void
     */
    public function testLiveDeadlinesReturnsBothDeadlinesOfALiveSession(): void
    {
        $idle     = $this->now->addHour();
        $absolute = $this->now->addDay();

        self::assertSame([$idle, $absolute], TokenLifetimes::liveDeadlines($this->device($idle, $absolute), $this->now));
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

    /**
     * Build a device with the given deadlines, expecting each to be read once
     * per check.
     *
     * @param  ?\Carbon\CarbonInterface  $idle
     * @param  ?\Carbon\CarbonInterface  $absolute
     * @param  int  $checks
     * @return \SineMacula\Laravel\Authentication\Contracts\Device
     */
    private function device(?CarbonInterface $idle, ?CarbonInterface $absolute, int $checks = 1): Device
    {
        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getIdleExpiresAt')->times($checks)->andReturn($idle);
        $device->shouldReceive('getAbsoluteExpiresAt')->times($checks)->andReturn($absolute);

        return $device;
    }
}
