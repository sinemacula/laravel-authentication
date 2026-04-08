<?php

declare(strict_types = 1);

namespace Tests\Unit\Listeners;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(UpdateDeviceTimestamp::class)]
final class UpdateDeviceTimestampTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Shared timestamp format used by the listener-state assertions. */
    private const string DATETIME_FORMAT = 'Y-m-d H:i:s';

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

        $device = new StubDevice;
        $device->save();

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

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
        $device = \Mockery::mock(Device::class);
        $device->shouldNotReceive('forceFill');
        $device->shouldNotReceive('save');

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

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

        $device = new StubDevice;
        $device->save();

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertInstanceOf(Carbon::class, $fresh->last_logged_in_at);
        self::assertSame(
            $frozen->format(self::DATETIME_FORMAT),
            $fresh->last_logged_in_at->format(self::DATETIME_FORMAT),
        );
    }

    /**
     * Asserts the listener skips the DB write when the stored
     * timestamp is still within the configured throttle window — the
     * debounce prevents a per-request hot-spot on the device row.
     *
     * @return void
     */
    public function testHandleSkipsWriteWithinThrottleWindow(): void
    {
        config()->set('authentication.device.last_seen_throttle_seconds', 60);

        $initial = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($initial);

        $device = new StubDevice;
        $device->forceFill(['last_logged_in_at' => $initial])->save();

        $advanced = $initial->copy()->addSeconds(30);
        Carbon::setTestNow($advanced);

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertInstanceOf(Carbon::class, $fresh->last_logged_in_at);
        self::assertSame(
            $initial->format(self::DATETIME_FORMAT),
            $fresh->last_logged_in_at->format(self::DATETIME_FORMAT),
            'Debounce window should prevent the listener from writing within the throttle period.',
        );
    }

    /**
     * Asserts the listener writes once the stored timestamp is older
     * than the configured throttle window.
     *
     * @return void
     */
    public function testHandleWritesOnceThrottleWindowHasElapsed(): void
    {
        config()->set('authentication.device.last_seen_throttle_seconds', 60);

        $initial = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($initial);

        $device = new StubDevice;
        $device->forceFill(['last_logged_in_at' => $initial])->save();

        $advanced = $initial->copy()->addSeconds(61);
        Carbon::setTestNow($advanced);

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertInstanceOf(Carbon::class, $fresh->last_logged_in_at);
        self::assertSame(
            $advanced->format(self::DATETIME_FORMAT),
            $fresh->last_logged_in_at->format(self::DATETIME_FORMAT),
        );
    }

    /**
     * Asserts the listener is invokable — registering it as a plain
     * class name via `Event::listen` continues to work.
     *
     * @return void
     */
    public function testInvokeIsEquivalentToHandle(): void
    {
        $now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        $device = new StubDevice;
        $device->save();

        $listener = new UpdateDeviceTimestamp;
        $listener(new DeviceAuthenticated('api', $device));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertInstanceOf(Carbon::class, $fresh->last_logged_in_at);
        self::assertTrue($now->equalTo($fresh->last_logged_in_at));
    }

    /**
     * Define the test environment: in-memory sqlite connection.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }
}
