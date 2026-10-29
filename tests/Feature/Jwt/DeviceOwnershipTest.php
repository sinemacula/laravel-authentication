<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Jwt\DeviceOwnership;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for `DeviceOwnership`, which reads a device row's owner and
 * decides whether an identity is that owner.
 *
 * Runs on the Testbench application because building the `authenticatable`
 * relation needs a database connection, although no query is made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceOwnership::class)]
final class DeviceOwnershipTest extends TestCase
{
    use InteractsWithDevices;

    /**
     * The owner key is the device row's owner key column as a string, or `null`
     * when the row records none.
     *
     * @return void
     */
    public function testOwnerKeyReadsTheOwnerKeyColumn(): void
    {
        self::assertSame('9', DeviceOwnership::ownerKey($this->device(StubIdentity::class, '9')));
        self::assertSame('9', DeviceOwnership::ownerKey($this->device(StubIdentity::class, 9)));
        self::assertNull(DeviceOwnership::ownerKey($this->device(StubIdentity::class, null)));
    }

    /**
     * Rows of `[identity, expected]` against a `StubIdentity` device owned by
     * key `9`.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity, 1: bool}>
     */
    public static function provideIdentities(): iterable
    {
        yield from [
            'the owner'                        => [static fn (): Identity => (new StubIdentity)->forceFill(['id' => 9]), true],
            'the owner with a string key'      => [static fn (): Identity => (new StubIdentity)->forceFill(['id' => '9']), true],
            'the owner model with another key' => [static fn (): Identity => (new StubIdentity)->forceFill(['id' => 10]), false],
            'another model with the owner key' => [static fn (): Identity => (new StubPrincipal)->forceFill(['id' => 9]), false],
            'an identity that is not a model'  => [static fn (): Identity => \Mockery::mock(Identity::class), false],
        ];
    }

    /**
     * Only an Eloquent identity of the device row's morph type with the device
     * row's owner key is the owner.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideIdentities')]
    public function testIsOwnerAcceptsOnlyTheExactOwner(\Closure $identity, bool $expected): void
    {
        self::assertSame($expected, DeviceOwnership::isOwner($this->device(StubIdentity::class, '9'), $identity()));
    }

    /**
     * A device row with no owner key has no owner, so no identity matches it,
     * not even one whose key is also empty.
     *
     * @return void
     */
    public function testIsOwnerRejectsEveryIdentityForADeviceWithoutAnOwnerKey(): void
    {
        self::assertFalse(DeviceOwnership::isOwner($this->device(StubIdentity::class, null), new StubIdentity));
    }

    /**
     * `DeviceOwnership` is a static utility; instantiation is disallowed via
     * the private constructor so consumers cannot create a stateful
     * device-ownership helper. Reflection invokes the private constructor so
     * the line is covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(DeviceOwnership::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(DeviceOwnership::class, $instance);
    }

    /**
     * A device whose recorded owner type is mapped through the morph map, or is
     * not a class at all, is judged by the class the type names.
     *
     * @return void
     */
    public function testAMachineOwnedDeviceIsJudgedByTheClassItsTypeNames(): void
    {
        $device = new StubDevice;

        self::assertFalse(DeviceOwnership::isMachineOwned($device));

        $device->forceFill(['authenticatable_type' => MachineClient::class]);

        self::assertTrue(DeviceOwnership::isMachineOwned($device));

        $device->forceFill(['authenticatable_type' => 'not-a-class']);

        self::assertFalse(DeviceOwnership::isMachineOwned($device));

        $device->forceFill(['authenticatable_type' => IntegrationIdentity::class]);

        self::assertFalse(DeviceOwnership::isMachineOwned($device));

        Relation::morphMap(['robot' => MachineClient::class]);

        try {
            $device->forceFill(['authenticatable_type' => 'robot']);

            self::assertTrue(DeviceOwnership::isMachineOwned($device));
        } finally {
            Relation::morphMap([], false);
        }
    }

    /**
     * Build an unsaved device row recording the supplied owner.
     *
     * @param  string  $type
     * @param  int|string|null  $key
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function device(string $type, int|string|null $key): StubDevice
    {
        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => $type,
            'authenticatable_id'   => $key,
        ]);

        return $device;
    }
}
