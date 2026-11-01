<?php

declare(strict_types = 1);

namespace Tests\Feature\SessionRecords;

use Illuminate\Support\Carbon;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for judging whether a guard may authenticate on a named
 * session, for which principal, and with tokens issued since when.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnedSession::class)]
final class OwnedSessionTest extends TestCase
{
    use InteractsWithSessionRecords, MockeryPHPUnitIntegration;

    /**
     * Rows of `[guard, revoked seconds ago or null, idle deadline in seconds,
     * status, the refusal]`, in the order the reasons are judged; the absolute
     * deadline is always two hours away.
     *
     * @return iterable<string, array{0: ?string, 1: ?int, 2: int, 3: string, 4: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideSessions(): iterable
    {
        yield 'a live session of the guard' => ['api', null, 3600, 'active', null];
        yield 'another guard, revoked, pending and ended' => ['admin', 60, 0, 'pending', FailureReason::SESSION_GUARD_MISMATCH];
        yield 'no guard' => [null, null, 3600, 'active', FailureReason::SESSION_GUARD_MISMATCH];
        yield 'revoked, pending and ended' => ['api', 60, 0, 'pending', FailureReason::SESSION_REVOKED];
        yield 'pending and ended' => ['api', null, 0, 'pending', FailureReason::SESSION_PENDING];
        yield 'pending' => ['api', null, 3600, 'pending', FailureReason::SESSION_PENDING];
        yield 'ended' => ['api', null, 0, 'active', FailureReason::SESSION_EXPIRED];
    }

    /**
     * The guard may authenticate only on a live, active session of its own;
     * otherwise the first reason that applies, guard before revocation before a
     * pending status before the deadlines.
     *
     * @param  ?string  $guard
     * @param  ?int  $revokedAgo
     * @param  int  $idleIn
     * @param  string  $status
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $refusal
     * @return void
     */
    #[DataProvider('provideSessions')]
    public function testTheGuardMayAuthenticateOnlyOnALiveSessionOfItsOwn(?string $guard, ?int $revokedAgo, int $idleIn, string $status, ?FailureReason $refusal): void
    {
        $now     = Carbon::now()->startOfSecond();
        $session = new StubSession([
            'status'              => $status,
            'guard'               => $guard,
            'revoked_at'          => $revokedAgo === null ? null : $now->copy()->subSeconds($revokedAgo),
            'idle_expires_at'     => $now->copy()->addSeconds($idleIn),
            'absolute_expires_at' => $now->copy()->addHours(2),
        ]);

        self::assertSame($refusal, OwnedSession::refusal($session, 'api', $now));
    }

    /**
     * A session of another guard that was loaded without its revocation is
     * still reported as the misconfiguration it is.
     *
     * @return void
     */
    public function testASessionLoadedWithoutItsRevocationIsReportedWhateverItsGuard(): void
    {
        $this->expectException(\LogicException::class);

        OwnedSession::refusal(
            new StubSession(['status' => 'active', 'guard' => 'admin', 'idle_expires_at' => Carbon::now(), 'absolute_expires_at' => Carbon::now()]),
            'api',
            Carbon::now(),
        );
    }

    /**
     * A session loaded without its status is reported as the misconfiguration
     * it is, whatever its guard, rather than taken for an active one.
     *
     * @return void
     */
    public function testASessionLoadedWithoutItsStatusIsReportedWhateverItsGuard(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('getStatusName()');

        OwnedSession::refusal(
            new StubSession(['guard' => 'admin', 'revoked_at' => null, 'idle_expires_at' => Carbon::now(), 'absolute_expires_at' => Carbon::now()]),
            'api',
            Carbon::now(),
        );
    }

    /**
     * Rows of `[principal type the session records, identifier it records,
     * acts as the principal]` against a plain principal identified `5`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: bool}>
     */
    public static function provideRecordedPrincipals(): iterable
    {
        yield 'the principal' => [PlainPrincipalFixture::class, '5', true];
        yield 'another identifier' => [PlainPrincipalFixture::class, '6', false];
        yield 'another type with the identifier' => [StubIdentity::class, '5', false];
        yield 'no principal' => [null, null, false];
    }

    /**
     * A session acts as a principal only when it records that principal's type
     * and identifier, comparing integer and string identifiers alike.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @param  bool  $actsAs
     * @return void
     */
    #[DataProvider('provideRecordedPrincipals')]
    public function testASessionActsOnlyAsThePrincipalItRecords(?string $type, ?string $id, bool $actsAs): void
    {
        $session = new StubSession(['principal_type' => $type, 'principal_id' => $id]);

        self::assertSame($actsAs, OwnedSession::actsAs($session, new PlainPrincipalFixture(5)));
    }

    /**
     * A session that is not an Eloquent model implementing the Eloquent session
     * contract cannot record a principal, so it acts as none.
     *
     * @return void
     */
    public function testASessionThatCannotRecordAPrincipalActsAsNone(): void
    {
        $principal = new PlainPrincipalFixture(5);

        self::assertFalse(OwnedSession::actsAs(\Mockery::mock(Session::class), $principal));
        self::assertFalse(OwnedSession::actsAs(\Mockery::mock(EloquentSession::class), $principal));
    }

    /**
     * Rows of `[seconds from the switch to the token's issue time, or null for
     * a session that never switched, issue time is whole, accepted]`.
     *
     * @return iterable<string, array{0: ?int, 1: bool, 2: bool}>
     */
    public static function provideIssueTimes(): iterable
    {
        yield 'never switched' => [null, true, true];
        yield 'never switched, no whole issue time' => [null, false, true];
        yield 'issued the second before the switch' => [-1, true, false];
        yield 'issued in the switch second' => [0, true, true];
        yield 'issued after the switch' => [1, true, true];
        yield 'no whole issue time after a switch' => [1, false, false];
    }

    /**
     * A token is held to the session's last principal switch: one issued before
     * the switch second is not, and one whose issue time is not whole cannot be
     * placed after it.
     *
     * @param  ?int  $offset
     * @param  bool  $whole
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideIssueTimes')]
    public function testATokenIsHeldToTheLastPrincipalSwitch(?int $offset, bool $whole, bool $accepted): void
    {
        $switched = Carbon::now()->startOfSecond();
        $session  = new StubSession(['switched_at' => $offset === null ? null : $switched]);
        $issuedAt = $switched->getTimestamp() + ($offset ?? 0);

        self::assertSame($accepted, OwnedSession::isIssuedSinceSwitch($session, $whole ? $issuedAt : (string) $issuedAt));
    }

    /**
     * A session loaded without its switch time fails closed rather than reading
     * as never switched.
     *
     * @return void
     */
    public function testASessionLoadedWithoutItsSwitchTimeIsReported(): void
    {
        $this->expectException(\LogicException::class);

        OwnedSession::isIssuedSinceSwitch(new StubSession, 1);
    }

    /**
     * `OwnedSession` is a static utility; reflection invokes the private
     * constructor so the line is covered while still documenting the access
     * modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(OwnedSession::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(OwnedSession::class, $instance);
    }
}
