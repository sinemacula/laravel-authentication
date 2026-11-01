<?php

declare(strict_types = 1);

namespace Tests\Unit\SessionRecords;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;

/**
 * Unit tests for the deadline rule every session follows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionDeadlines::class)]
final class SessionDeadlinesTest extends TestCase
{
    use MockeryPHPUnitIntegration;

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
        $now     = $this->now->startOfSecond();
        $session = $this->session($idleIn === null ? null : $now->addSeconds($idleIn), $absoluteIn === null ? null : $now->addSeconds($absoluteIn), 2);

        self::assertSame($ended, SessionDeadlines::hasEnded($session, $this->now));
        self::assertSame($ended, SessionDeadlines::liveDeadlines($session, $this->now) === null);
    }

    /**
     * A live session's deadlines are returned as the session reported them.
     *
     * @return void
     */
    public function testLiveDeadlinesReturnsBothDeadlinesOfALiveSession(): void
    {
        $idle     = $this->now->addHour();
        $absolute = $this->now->addDay();

        self::assertSame([$idle, $absolute], SessionDeadlines::liveDeadlines($this->session($idle, $absolute), $this->now));
    }

    /**
     * `SessionDeadlines` is a static utility; reflection invokes the private
     * constructor so the line is covered while still documenting the access
     * modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SessionDeadlines::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(SessionDeadlines::class, $instance);
    }

    /**
     * Build a session with the given deadlines, expecting each to be read once
     * per check.
     *
     * @param  ?\Carbon\CarbonInterface  $idle
     * @param  ?\Carbon\CarbonInterface  $absolute
     * @param  int  $checks
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     */
    private function session(?CarbonInterface $idle, ?CarbonInterface $absolute, int $checks = 1): Session
    {
        $session = \Mockery::mock(Session::class);
        $session->shouldReceive('getIdleExpiresAt')->times($checks)->andReturn($idle);
        $session->shouldReceive('getAbsoluteExpiresAt')->times($checks)->andReturn($absolute);

        return $session;
    }
}
