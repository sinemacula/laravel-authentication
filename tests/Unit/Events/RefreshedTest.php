<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Refreshed;

/**
 * Refreshed event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(Refreshed::class)]
final class RefreshedTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Asserts the event retains the guard name supplied at construction.
     *
     * @return void
     */
    public function testStoresGuardNameOnConstruction(): void
    {
        $event = $this->makeEvent('api');

        self::assertSame('api', $event->guard);
    }

    /**
     * Asserts the event retains the identity instance supplied at construction.
     *
     * @return void
     */
    public function testStoresIdentityOnConstruction(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $event = new Refreshed(
            'api',
            $identity,
            \Mockery::mock(Principal::class),
            \Mockery::mock(Device::class),
        );

        self::assertSame($identity, $event->identity);
    }

    /**
     * Asserts the event retains the principal instance supplied at
     * construction.
     *
     * @return void
     */
    public function testStoresPrincipalOnConstruction(): void
    {
        $principal = \Mockery::mock(Principal::class);

        $event = new Refreshed(
            'api',
            \Mockery::mock(Identity::class),
            $principal,
            \Mockery::mock(Device::class),
        );

        self::assertSame($principal, $event->principal);
    }

    /**
     * Asserts the event retains the device instance supplied at construction.
     *
     * @return void
     */
    public function testStoresDeviceOnConstruction(): void
    {
        $device = \Mockery::mock(Device::class);

        $event = new Refreshed(
            'api',
            \Mockery::mock(Identity::class),
            \Mockery::mock(Principal::class),
            $device,
        );

        self::assertSame($device, $event->device);
    }

    /**
     * Build a Refreshed event with the supplied guard name and fresh
     * mock collaborators.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Events\Refreshed
     */
    private function makeEvent(string $guard): Refreshed
    {
        return new Refreshed(
            $guard,
            \Mockery::mock(Identity::class),
            \Mockery::mock(Principal::class),
            \Mockery::mock(Device::class),
        );
    }
}
