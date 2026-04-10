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
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;

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
     * The `Refreshed` event composes Laravel's `SerializesModels`
     * trait so it survives a queued-listener round trip. Reflection
     * guards against accidentally dropping the trait.
     *
     * @return void
     */
    public function testUsesSerializesModelsTrait(): void
    {
        self::assertContains(
            \Illuminate\Queue\SerializesModels::class,
            (new \ReflectionClass(Refreshed::class))->getTraitNames(),
        );
    }

    /**
     * The event is `serialize`/`unserialize` round-trippable with
     * plain-object (non-Eloquent) contract implementations as
     * payload. Pins the runtime serialisation path - if
     * `SerializesModels` is dropped or the event gains a
     * non-serialisable property, the round trip fails.
     *
     * Uses plain-object fixtures rather than Eloquent stubs so the
     * assertion does not require a database connection;
     * `SerializesModels` only replaces Eloquent models with lazy
     * identifiers, leaving arbitrary objects intact.
     *
     * @return void
     */
    public function testSurvivesSerializeUnserializeRoundTrip(): void
    {
        $event = new Refreshed(
            'api',
            new PlainIdentityFixture(42),
            new PlainPrincipalFixture(7),
            new PlainDeviceFixture('01HZZ-device-id'),
        );

        /** @var \SineMacula\Laravel\Authentication\Events\Refreshed $roundTripped */
        $roundTripped = unserialize(serialize($event));

        self::assertInstanceOf(Refreshed::class, $roundTripped);
        self::assertSame('api', $roundTripped->guard);
        self::assertInstanceOf(PlainIdentityFixture::class, $roundTripped->identity);
        self::assertInstanceOf(PlainPrincipalFixture::class, $roundTripped->principal);
        self::assertInstanceOf(PlainDeviceFixture::class, $roundTripped->device);
        self::assertSame(42, $roundTripped->identity->getAuthIdentifier());
        self::assertSame(7, $roundTripped->principal->getPrincipalIdentifier());
        self::assertSame('01HZZ-device-id', $roundTripped->device->getDeviceIdentifier());
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
