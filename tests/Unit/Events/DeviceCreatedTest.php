<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Queue\SerializesModels;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * DeviceCreated event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceCreated::class)]
final class DeviceCreatedTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The event carries the whole context of a created device.
     *
     * @return void
     */
    public function testStoresTheContextOnConstruction(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class);
        $tenant    = \Mockery::mock(Tenant::class);
        $device    = \Mockery::mock(Device::class);
        $client    = new ClientContext('203.0.113.7', 'agent');

        $event = new DeviceCreated('api', $identity, $principal, $tenant, $device, 'password', $client);

        self::assertSame('api', $event->guard);
        self::assertSame($identity, $event->identity);
        self::assertSame($principal, $event->principal);
        self::assertSame($tenant, $event->tenant);
        self::assertSame($device, $event->device);
        self::assertSame('password', $event->method);
        self::assertSame($client, $event->client);
    }

    /**
     * Queued listeners get the models re-fetched, as Laravel's
     * `SerializesModels` does.
     *
     * @return void
     */
    public function testSerializesItsModels(): void
    {
        self::assertContains(SerializesModels::class, class_uses(DeviceCreated::class));
    }
}
