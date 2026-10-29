<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\UuidKeyedPrincipal;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for the shipped device's `principal()` relation against
 * real rows: the principal columns hold any key type as a string, so a device
 * resolves an integer-keyed and a UUID-keyed principal alike, lazily and
 * eagerly, on whichever engine the suite runs against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Device::class)]
final class DevicePrincipalIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /**
     * Create an integer-keyed and a UUID-keyed principal table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('uuid_keyed_principals', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the principal tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('uuid_keyed_principals');
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * A device loaded on its own resolves its integer-keyed or UUID-keyed
     * principal, and a device that records none has none.
     *
     * @return void
     */
    public function testResolvesAPrincipalOfAnyKeyType(): void
    {
        [$integerKeyed, $uuidKeyed] = $this->principals();

        $first  = $this->deviceActingAs($integerKeyed);
        $second = $this->deviceActingAs($uuidKeyed);
        $none   = $this->deviceActingAs(null);

        $this->assertResolves($integerKeyed, $this->reload($first)->principal);
        $this->assertResolves($uuidKeyed, $this->reload($second)->principal);

        self::assertNull($this->reload($none)->principal);
    }

    /**
     * Eager loading the principals of devices acting as principals of both key
     * types resolves each one.
     *
     * @return void
     */
    public function testEagerLoadsPrincipalsOfEveryKeyType(): void
    {
        [$integerKeyed, $uuidKeyed] = $this->principals();

        $first  = $this->deviceActingAs($integerKeyed);
        $second = $this->deviceActingAs($uuidKeyed);

        $devices = Device::query()->with('principal')->get()->keyBy(static fn (Device $device): string => $device->id);

        self::assertCount(2, $devices);

        foreach ([[$first, $integerKeyed], [$second, $uuidKeyed]] as [$device, $principal]) {

            $loaded = $devices->get($device->id);

            self::assertInstanceOf(Device::class, $loaded);
            self::assertTrue($loaded->relationLoaded('principal'));

            $this->assertResolves($principal, $loaded->principal);
        }
    }

    /**
     * Persist one integer-keyed and one UUID-keyed principal.
     *
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \Tests\Integration\Fixtures\UuidKeyedPrincipal}
     */
    private function principals(): array
    {
        $integerKeyed            = new StubPrincipal;
        $integerKeyed->email     = 'integer-keyed@example.test';
        $integerKeyed->password  = 'irrelevant';
        $integerKeyed->is_active = true;
        $integerKeyed->save();

        $uuidKeyed = new UuidKeyedPrincipal;
        $uuidKeyed->save();

        return [$integerKeyed, $uuidKeyed];
    }

    /**
     * Persist a live device of the integer-keyed identity acting as the given
     * principal, or as none.
     *
     * @param  ?\Illuminate\Database\Eloquent\Model  $principal
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function deviceActingAs(?Model $principal): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => '1',
            'principal_type'       => $principal?->getMorphClass(),
            'principal_id'         => $principal === null ? null : (string) $principal->getKey(), // @phpstan-ignore cast.string
        ])->save();

        return $device;
    }

    /**
     * Load a device again from the database.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function reload(Device $device): Device
    {
        return Device::query()->whereKey($device->getKey())->firstOrFail();
    }

    /**
     * Assert that a resolved principal is the expected row.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $expected
     * @param  mixed  $resolved
     * @return void
     */
    private function assertResolves(Model $expected, mixed $resolved): void
    {
        self::assertInstanceOf($expected::class, $resolved);
        self::assertTrue($expected->is($resolved));
    }
}
