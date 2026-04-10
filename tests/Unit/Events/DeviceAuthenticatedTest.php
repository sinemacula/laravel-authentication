<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;

/**
 * DeviceAuthenticated event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(DeviceAuthenticated::class)]
final class DeviceAuthenticatedTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Asserts the event retains the guard name supplied at construction.
     *
     * @return void
     */
    public function testStoresGuardNameOnConstruction(): void
    {
        $device = \Mockery::mock(Device::class);

        $event = new DeviceAuthenticated('api', $device);

        self::assertSame('api', $event->guard);
    }

    /**
     * Asserts the event retains the device instance supplied at construction.
     *
     * @return void
     */
    public function testStoresDeviceOnConstruction(): void
    {
        $device = \Mockery::mock(Device::class);

        $event = new DeviceAuthenticated('api', $device);

        self::assertSame($device, $event->device);
    }
}
