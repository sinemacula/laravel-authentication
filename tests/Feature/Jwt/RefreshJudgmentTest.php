<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;
use SineMacula\Laravel\Authentication\Jwt\RefreshJudgment;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\TestCase;

/**
 * Feature tests of judging a presented refresh rotation id against its session:
 * the session's state first, then the id, current, previous inside the grace
 * window, or a replay.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshJudgment::class)]
final class RefreshJudgmentTest extends TestCase
{
    /** @var string The rotation id the session was rotated from. */
    private const string PREVIOUS = 'previous-rotation-id';

    /** @var \Carbon\CarbonImmutable The time of judgement. */
    private CarbonImmutable $now;

    /**
     * Fix the time of judgement.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
    }

    /**
     * The judgement is a utility; it cannot be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(RefreshJudgment::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(RefreshJudgment::class, $instance);
    }

    /**
     * The current rotation id of a live session is current, with the session's
     * absolute deadline.
     *
     * @return void
     */
    public function testTheCurrentIdIsCurrent(): void
    {
        $session = $this->rotatedSession(10);
        $verdict = $this->judge($session, RefreshTokenHasher::successor(self::PREVIOUS));

        self::assertIsArray($verdict);
        self::assertSame(RotationMatch::CURRENT, $verdict[0]);
        self::assertSame($this->now->addDays(180)->getTimestamp(), $verdict[1]?->getTimestamp());
    }

    /**
     * A live session with no absolute deadline is judged as any other: its
     * current id is current, with no absolute deadline for the rotation to
     * keep.
     *
     * @return void
     */
    public function testTheCurrentIdOfASessionWithoutAnAbsoluteDeadlineIsCurrent(): void
    {
        $session = $this->rotatedSession(10);

        $session->setAttribute('absolute_expires_at', null);

        self::assertSame([RotationMatch::CURRENT, null], $this->judge($session, RefreshTokenHasher::successor(self::PREVIOUS)));
    }

    /**
     * The id the current one replaced, presented inside the grace window, is
     * the previous one.
     *
     * @return void
     */
    public function testThePreviousIdInsideTheGraceWindowIsPrevious(): void
    {
        $verdict = $this->judge($this->rotatedSession(29), self::PREVIOUS);

        self::assertIsArray($verdict);
        self::assertSame(RotationMatch::PREVIOUS, $verdict[0]);
        self::assertSame($this->now->addDays(180)->getTimestamp(), $verdict[1]?->getTimestamp());
    }

    /**
     * Rows of `[session changes, presented id, grace seconds]` judged as a
     * replay.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: int}>
     */
    public static function provideReplays(): iterable
    {
        yield from [
            'an unknown id'                   => [[], 'unknown-rotation-id', 30],
            'the previous id at the boundary' => [['refresh_rotated_at' => '-30 seconds'], self::PREVIOUS, 30],
            'the previous id, grace off'      => [[], self::PREVIOUS, 0],
            'no previous digest'              => [['previous_refresh_key' => null], self::PREVIOUS, 30],
            'no rotation time'                => [['refresh_rotated_at' => null], self::PREVIOUS, 30],
            'a current id not its successor'  => [['refresh_key' => RefreshTokenHasher::hash('elsewhere')], self::PREVIOUS, 30],
        ];
    }

    /**
     * Anything other than the current id, or the previous one inside the grace
     * window whose successor is the current one, is a replay.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $presented
     * @param  int  $grace
     * @return void
     *
     * @throws \DateMalformedStringException
     */
    #[DataProvider('provideReplays')]
    public function testAnythingElseIsAReplay(array $changes, string $presented, int $grace): void
    {
        $session = $this->rotatedSession(10);

        $this->change($session, $changes);

        self::assertSame(FailureReason::ROTATION_REUSE, $this->judge($session, $presented, $grace));
    }

    /**
     * Rows of `[session changes, failure]` for a session that is not live.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideEndedSessions(): iterable
    {
        yield from [
            'revoked'                   => [['revoked_at' => '-1 second'], FailureReason::SESSION_REVOKED],
            'revoked and ended'         => [['revoked_at' => '-1 second', 'idle_expires_at' => '-1 second'], FailureReason::SESSION_REVOKED],
            'idle deadline reached'     => [['idle_expires_at' => '+0 seconds'], FailureReason::SESSION_EXPIRED],
            'absolute deadline reached' => [['absolute_expires_at' => '+0 seconds'], FailureReason::SESSION_EXPIRED],
            'no idle deadline'          => [['idle_expires_at' => null], FailureReason::SESSION_EXPIRED],
            'no absolute, idle reached' => [['absolute_expires_at' => null, 'idle_expires_at' => '+0 seconds'], FailureReason::SESSION_EXPIRED],
            'ended with no credential'  => [['idle_expires_at' => '-1 second', 'refresh_key' => null], FailureReason::SESSION_EXPIRED],
            'no credential'             => [['refresh_key' => null], FailureReason::REFRESH_KEY_MISSING],
        ];
    }

    /**
     * A revoked session, an ended session and a session with no credential fail
     * for that reason before the id is compared.
     *
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \DateMalformedStringException
     */
    #[DataProvider('provideEndedSessions')]
    public function testASessionWithoutALiveSessionFailsFirst(array $changes, FailureReason $reason): void
    {
        $session = $this->rotatedSession(10);

        $this->change($session, $changes);

        self::assertSame($reason, $this->judge($session, RefreshTokenHasher::successor(self::PREVIOUS)));
    }

    /**
     * A session rotated from the previous id the given seconds ago, and live
     * for days.
     *
     * @param  int  $rotatedSecondsAgo
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function rotatedSession(int $rotatedSecondsAgo): Session
    {
        $session = new Session;
        $session->forceFill([
            'revoked_at'           => null,
            'idle_expires_at'      => $this->now->addDays(30),
            'absolute_expires_at'  => $this->now->addDays(180),
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::PREVIOUS)),
            'previous_refresh_key' => RefreshTokenHasher::hash(self::PREVIOUS),
            'refresh_rotated_at'   => $this->now->subSeconds($rotatedSecondsAgo),
        ]);

        return $session;
    }

    /**
     * Apply the changes to the session: a time column given as a string is
     * moved that far from now.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  array<string, mixed>  $changes
     * @return void
     *
     * @throws \DateMalformedStringException
     */
    private function change(Session $session, array $changes): void
    {
        foreach ($changes as $column => $value) {
            $session->setAttribute($column, is_string($value) && str_ends_with($column, '_at') ? $this->now->modify($value) : $value);
        }
    }

    /**
     * Judge the presented id against the session now, with the grace window.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  string  $presented
     * @param  int  $grace
     * @return array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch, 1: ?\Carbon\CarbonInterface}|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    private function judge(Session $session, string $presented, int $grace = 30): array|FailureReason
    {
        return RefreshJudgment::classify($session, $presented, $this->now, new TokenLifetimes(5, 60 * 24 * 30, 60 * 24 * 180, $grace));
    }
}
