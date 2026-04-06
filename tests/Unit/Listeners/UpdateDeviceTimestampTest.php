<?php

declare(strict_types=1);

namespace Tests\Unit\Listeners;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use Tests\Unit\Stubs\StubDevice;

/**
 * Unit tests for the UpdateDeviceTimestamp listener.
 *
 * Uses Orchestra Testbench with an in-memory sqlite connection and a
 * manually-created `stub_devices` table so the assertion against the
 * listener's persistence behaviour is exercised end-to-end without the
 * package migration.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class UpdateDeviceTimestampTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Define the test environment: in-memory sqlite connection.
     *
     * @param  \Illuminate\Foundation\Application $app The Testbench application under construction.
     * @return void
     */
    protected function defineEnvironment($app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }

    /**
     * Create the in-memory schema the listener will persist against.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_devices', static function (Blueprint $blueprint): void {

            $blueprint->ulid('id')->primary();
            $blueprint->string('os')->default('');
            $blueprint->string('refresh_key')->default('');
            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clock and drop the in-memory schema once
     * each test has completed.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        Schema::dropIfExists('stub_devices');

        parent::tearDown();
    }

    /**
     * Asserts the listener updates the `last_logged_in_at` timestamp
     * on a persisted Eloquent Device and saves the change to the
     * underlying store.
     *
     * @return void
     */
    public function testHandleUpdatesLastLoggedInAtForEloquentDevice(): void
    {
        $now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        $device = new StubDevice();
        $device->save();

        (new UpdateDeviceTimestamp())->handle(new DeviceAuthenticated('api', $device));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertInstanceOf(Carbon::class, $fresh->last_logged_in_at);
        self::assertTrue($now->equalTo($fresh->last_logged_in_at));
    }

    /**
     * Asserts the listener silently returns without invoking any
     * model-side methods when the device is not an Eloquent model.
     *
     * @return void
     */
    public function testHandleNoOpsForNonModelDevice(): void
    {
        $device = Mockery::mock(Device::class);
        $device->shouldNotReceive('forceFill');
        $device->shouldNotReceive('save');

        (new UpdateDeviceTimestamp())->handle(new DeviceAuthenticated('api', $device));

        self::assertTrue(true, 'Listener returned silently for a non-Model device.');
    }

    /**
     * Asserts the listener uses a frozen `Carbon::now()` when
     * `setTestNow()` is active.
     *
     * @return void
     */
    public function testHandleUsesFrozenCarbonNow(): void
    {
        $frozen = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($frozen);

        $device = new StubDevice();
        $device->save();

        (new UpdateDeviceTimestamp())->handle(new DeviceAuthenticated('api', $device));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertInstanceOf(Carbon::class, $fresh->last_logged_in_at);
        self::assertSame(
            $frozen->format('Y-m-d H:i:s'),
            $fresh->last_logged_in_at->format('Y-m-d H:i:s'),
        );
    }
}
