<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;

/**
 * Unit tests for the slots one sign-in takes on the limits of the accounts it
 * checks a secret for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccountAttempts::class)]
final class AccountAttemptsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Each account is reserved on the guard's sign-in flow under its class and
     * auth identifier when it is not a model, with no identifier, identifier
     * type or IP address.
     *
     * @return void
     */
    public function testAnAccountIsReservedUnderItsClassAndKey(): void
    {
        $subjects = [];

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->once()->andReturnUsing(static function (AttemptSubject $subject) use (&$subjects): AttemptReservation {
            $subjects[] = $subject;

            return new AttemptReservation($subject, null);
        });

        $identity = $this->identity(42);

        self::assertTrue((new AccountAttempts($limiter, 'staff'))->reserve($identity));
        self::assertSame('staff', $subjects[0]->guard);
        self::assertSame(AttemptFlow::SIGN_IN, $subjects[0]->flow);
        self::assertNull($subjects[0]->identifier);
        self::assertNull($subjects[0]->identifierType);
        self::assertNull($subjects[0]->ip);
        self::assertSame("class\0" . $identity::class . "\x0042", $subjects[0]->account);
        self::assertSame($subjects[0]->account, AccountAttempts::account($identity));
    }

    /**
     * Granted reservations are held: their windows are reported together for a
     * pending sign-in, and releasing gives each back once; a refused one is
     * neither held nor given back.
     *
     * @return void
     */
    public function testGrantedReservationsAreHeldUntilReleased(): void
    {
        $subject = new AttemptSubject('api', AttemptFlow::SIGN_IN, null, null, null, 'account');
        $first   = new AttemptReservation($subject, null, ['first' => '2026-04-06 12:05:00']);
        $refused = new AttemptReservation($subject, 30);
        $second  = new AttemptReservation($subject, null, ['second' => '2026-04-06 12:10:00']);
        $given   = [];

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->times(3)->andReturn($first, $refused, $second);
        $limiter->shouldReceive('release')->twice()->andReturnUsing(static function (AttemptReservation $reservation) use (&$given): void {
            $given[] = $reservation;
        });

        $attempts = new AccountAttempts($limiter, 'api');

        self::assertSame([], $attempts->windows());
        self::assertNull($attempts->refusedFor());
        self::assertTrue($attempts->reserve($this->identity(1)));
        self::assertNull($attempts->refusedFor());
        self::assertFalse($attempts->reserve($this->identity(2)));
        self::assertSame(30, $attempts->refusedFor());
        self::assertTrue($attempts->reserve($this->identity(3)));
        self::assertSame([['first' => '2026-04-06 12:05:00'], ['second' => '2026-04-06 12:10:00']], $attempts->windows());

        $attempts->release();

        self::assertSame([$first, $second], $given);
    }

    /**
     * One account checked twice holds two reservations with the same window:
     * both are reported for a pending sign-in, and releasing gives both back.
     *
     * @return void
     */
    public function testTwoReservationsOfOneAccountAreKeptApart(): void
    {
        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->twice()->andReturnUsing(
            static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, null, ['account' => '2026-04-06 12:05:00']),
        );
        $limiter->shouldReceive('release')->twice();

        $attempts = new AccountAttempts($limiter, 'api');
        $identity = $this->identity(7);

        self::assertTrue($attempts->reserve($identity));
        self::assertTrue($attempts->reserve($identity));
        self::assertSame([['account' => '2026-04-06 12:05:00'], ['account' => '2026-04-06 12:05:00']], $attempts->windows());

        $attempts->release();
    }

    /**
     * Build an identity with the auth identifier.
     *
     * @param  int  $key
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identity(int $key): Identity
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn($key);

        return $identity;
    }
}
