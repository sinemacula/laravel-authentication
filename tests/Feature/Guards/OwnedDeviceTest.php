<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\OwnedDevice;
use Tests\Concerns\InteractsWithDevices;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for finding a named device among an identity's own and judging
 * whether a guard may authenticate on it.
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

    /** @var string Well-formed id of the device named. */
    private const string DEVICE_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /**
     * No hint names no device, without building the identity's relation.
     *
     * @return void
     */
    public function testNoHintFindsNothingWithoutAQuery(): void
    {
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldNotReceive('devices');

        self::assertNull(OwnedDevice::find($identity, null));
    }

    /**
     * An identity that holds no devices finds none for any hint.
     *
     * @return void
     */
    public function testAnIdentityWithoutDevicesFindsNothing(): void
    {
        self::assertNull(OwnedDevice::find(\Mockery::mock(Identity::class), self::DEVICE_ID));
    }

    /**
     * A hint that cannot be a key of the device model is not looked up, and a
     * well-formed one is found through the relation.
     *
     * @return void
     */
    public function testAHintIsLookedUpOnlyWhenItCanBeAKey(): void
    {
        $device  = new StubDevice(['id' => self::DEVICE_ID]);
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')->andReturnSelf();
        $builder->shouldReceive('getModel')->andReturn(new StubDevice);
        $builder->shouldReceive('find')->once()->with(self::DEVICE_ID)->andReturn($device);

        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('devices')->twice()->andReturn($builder);

        self::assertNull(OwnedDevice::find($identity, 'not-a-uuid'));
        self::assertSame($device, OwnedDevice::find($identity, self::DEVICE_ID));
    }

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
}
