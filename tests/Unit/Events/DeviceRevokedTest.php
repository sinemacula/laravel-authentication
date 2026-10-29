<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use Tests\Unit\Stubs\PlainDeviceFixture;

/**
 * DeviceRevoked event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceRevoked::class)]
final class DeviceRevokedTest extends TestCase
{
    /**
     * The event carries the guard, the device, and the reason it was revoked.
     *
     * @return void
     */
    public function testCarriesTheGuardDeviceAndReason(): void
    {
        $device = new PlainDeviceFixture('device-1');

        $event = new DeviceRevoked('api', $device, RevocationReason::ROTATION_REUSE);

        self::assertSame('api', $event->guard);
        self::assertSame($device, $event->device);
        self::assertSame(RevocationReason::ROTATION_REUSE, $event->reason);
    }

    /**
     * The event serialises its models for queued listeners. It does not ask the
     * dispatcher to wait for a transaction: that would wait for whichever
     * transaction is open last on any connection, so the exchange instead
     * dispatches it once the device's own connection commits.
     *
     * @return void
     */
    public function testSerialisesModelsAndLeavesTheCommitToTheExchange(): void
    {
        $event = new DeviceRevoked('api', new PlainDeviceFixture('device-1'), RevocationReason::ROTATION_REUSE);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses($event));

        $roundTripped = unserialize(serialize($event));

        self::assertInstanceOf(DeviceRevoked::class, $roundTripped);
        self::assertSame('device-1', $roundTripped->device->getDeviceIdentifier());
        self::assertSame(RevocationReason::ROTATION_REUSE, $roundTripped->reason);
    }

    /**
     * The revocation reasons and the values stored on the device row.
     *
     * @return void
     */
    public function testRevocationReasonsAreTheStoredValues(): void
    {
        self::assertSame(['rotation_reuse'], array_map(static fn (RevocationReason $reason): string => $reason->value, RevocationReason::cases()));
    }
}
