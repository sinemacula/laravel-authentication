<?php

declare(strict_types = 1);

namespace Tests\Feature\Devices;

use Illuminate\Support\Carbon;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Devices\OwnedDevice;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use Tests\Concerns\InteractsWithDevices;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for judging whether a guard may authenticate on a named device,
 * for which principal, and with tokens issued since when.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnedDevice::class)]
final class OwnedDeviceTest extends TestCase
{
    use InteractsWithDevices, MockeryPHPUnitIntegration;

    /**
     * Rows of `[guard, revoked seconds ago or null, idle deadline in seconds,
     * the refusal]`, in the order the reasons are judged; the absolute deadline
     * is always two hours away.
     *
     * @return iterable<string, array{0: ?string, 1: ?int, 2: int, 3: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideDevices(): iterable
    {
        yield 'a live device of the guard' => ['api', null, 3600, null];
        yield 'another guard, revoked and ended' => ['admin', 60, 0, FailureReason::DEVICE_GUARD_MISMATCH];
        yield 'no guard' => [null, null, 3600, FailureReason::DEVICE_GUARD_MISMATCH];
        yield 'revoked and ended' => ['api', 60, 0, FailureReason::DEVICE_REVOKED];
        yield 'ended' => ['api', null, 0, FailureReason::SESSION_EXPIRED];
    }

    /**
     * The guard may authenticate only on a live device of its own; otherwise
     * the first reason that applies, guard before revocation before the
     * deadlines.
     *
     * @param  ?string  $guard
     * @param  ?int  $revokedAgo
     * @param  int  $idleIn
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $refusal
     * @return void
     */
    #[DataProvider('provideDevices')]
    public function testTheGuardMayAuthenticateOnlyOnALiveDeviceOfItsOwn(?string $guard, ?int $revokedAgo, int $idleIn, ?FailureReason $refusal): void
    {
        $now    = Carbon::now()->startOfSecond();
        $device = new StubDevice([
            'guard'               => $guard,
            'revoked_at'          => $revokedAgo === null ? null : $now->copy()->subSeconds($revokedAgo),
            'idle_expires_at'     => $now->copy()->addSeconds($idleIn),
            'absolute_expires_at' => $now->copy()->addHours(2),
        ]);

        self::assertSame($refusal, OwnedDevice::refusal($device, 'api', $now));
    }

    /**
     * A device of another guard that was loaded without its revocation is still
     * reported as the misconfiguration it is.
     *
     * @return void
     */
    public function testADeviceLoadedWithoutItsRevocationIsReportedWhateverItsGuard(): void
    {
        $this->expectException(\LogicException::class);

        OwnedDevice::refusal(new StubDevice(['guard' => 'admin', 'idle_expires_at' => Carbon::now(), 'absolute_expires_at' => Carbon::now()]), 'api', Carbon::now());
    }

    /**
     * Rows of `[principal type the device records, identifier it records,
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
     * A device acts as a principal only when it records that principal's type
     * and identifier, comparing integer and string identifiers alike.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @param  bool  $actsAs
     * @return void
     */
    #[DataProvider('provideRecordedPrincipals')]
    public function testADeviceActsOnlyAsThePrincipalItRecords(?string $type, ?string $id, bool $actsAs): void
    {
        $device = new StubDevice(['principal_type' => $type, 'principal_id' => $id]);

        self::assertSame($actsAs, OwnedDevice::actsAs($device, new PlainPrincipalFixture(5)));
    }

    /**
     * A device that is not an Eloquent model implementing the Eloquent device
     * contract cannot record a principal, so it acts as none.
     *
     * @return void
     */
    public function testADeviceThatCannotRecordAPrincipalActsAsNone(): void
    {
        $principal = new PlainPrincipalFixture(5);

        self::assertFalse(OwnedDevice::actsAs(\Mockery::mock(Device::class), $principal));
        self::assertFalse(OwnedDevice::actsAs(\Mockery::mock(EloquentDevice::class), $principal));
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
        $device   = new StubDevice(['principal_switched_at' => $offset === null ? null : $switched]);
        $issuedAt = $switched->getTimestamp() + ($offset ?? 0);

        self::assertSame($accepted, OwnedDevice::isIssuedSinceSwitch($device, $whole ? $issuedAt : (string) $issuedAt));
    }

    /**
     * A device loaded without its switch time fails closed rather than reading
     * as never switched.
     *
     * @return void
     */
    public function testADeviceLoadedWithoutItsSwitchTimeIsReported(): void
    {
        $this->expectException(\LogicException::class);

        OwnedDevice::isIssuedSinceSwitch(new StubDevice, 1);
    }

    /**
     * `OwnedDevice` is a static utility; reflection invokes the private
     * constructor so the line is covered while still documenting the access
     * modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(OwnedDevice::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(OwnedDevice::class, $instance);
    }
}
