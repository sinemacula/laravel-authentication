<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use Tests\Unit\Stubs\StubDevice;

/**
 * Feature tests for the UpdateDeviceTimestamp listener.
 *
 * Uses Orchestra Testbench with an in-memory sqlite connection and a
 * manually-created `stub_devices` table so the assertion against the listener's
 * persistence behaviour is exercised end-to-end without the package migration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UpdateDeviceTimestamp::class)]
final class UpdateDeviceTimestampTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Timestamp format for assertions. */
    private const string DATETIME_FORMAT = 'Y-m-d H:i:s';

    /**
     * Create the in-memory schema the listener will persist against.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_devices', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('os')->default('');
            $blueprint->string('refresh_key')->default('');
            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clock and drop the in-memory schema once each test
     * has completed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        Schema::dropIfExists('stub_devices');

        parent::tearDown();
    }

    /**
     * Asserts the listener updates the `last_logged_in_at` timestamp on a
     * persisted Eloquent Device and saves the change to the underlying store.
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
     * Asserts the listener silently returns for a generic `Device` payload that
     * does not satisfy the explicit Eloquent-backed persistence boundary.
     *
     * @return void
     */
    public function testHandleNoOpsForNonModelDevice(): void
    {
        $device = \Mockery::mock(Device::class);

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

        // No exception thrown and no persistence attempted - the listener
        // short-circuits for non-EloquentDevice payloads.
        self::assertTrue(true);
    }

    /**
     * Asserts the listener uses a frozen `Carbon::now()` when `setTestNow()`
     * is active.
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
     * Asserts the listener skips the DB write when the stored timestamp is
     * still within the configured throttle window - the debounce prevents a
     * per-request hot-spot on the device row.
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
     * Boundary test: when the elapsed time since the stored timestamp is
     * exactly the throttle window, the listener writes. Mutation guard against
     * the `>=` operator drifting to `>`.
     *
     * @return void
     */
    public function testHandleWritesAtExactThrottleWindowBoundary(): void
    {
        config()->set('authentication.device.last_seen_throttle_seconds', 60);

        $initial = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($initial);

        $device = new StubDevice;
        $device->forceFill(['last_logged_in_at' => $initial])->save();

        $advanced = $initial->copy()->addSeconds(60);
        Carbon::setTestNow($advanced);

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertSame(
            $advanced->format(self::DATETIME_FORMAT),
            $fresh->last_logged_in_at?->format(self::DATETIME_FORMAT),
            'Listener should write when elapsed === throttle window.',
        );
    }

    /**
     * Asserts the listener writes once the stored timestamp is older than the
     * configured throttle window.
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
     * A non-positive `device.last_seen_throttle_seconds` config disables the
     * throttle and the listener writes on every dispatch, even when the stored
     * timestamp matches `now`.
     *
     * @return void
     */
    public function testHandleWritesAlwaysWhenThrottleDisabled(): void
    {
        config()->set('authentication.device.last_seen_throttle_seconds', 0);

        $initial = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($initial);

        $device = new StubDevice;
        $device->forceFill(['last_logged_in_at' => $initial])->save();

        // Advance the clock by 1 second so the assertion can detect a write
        // happened (the column should now be at $advanced, not $initial).
        $advanced = $initial->copy()->addSeconds(1);
        Carbon::setTestNow($advanced);

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertSame(
            $advanced->format(self::DATETIME_FORMAT),
            $fresh->last_logged_in_at?->format(self::DATETIME_FORMAT),
            'Throttle disabled - the listener should always write.',
        );
    }

    /**
     * The listener no-ops on an unpersisted Eloquent device (the `$exists`
     * flag is false), so the in-memory model is not touched and the database
     * is not written to. Pins the `!$device->exists` short-circuit in
     * `__invoke()`.
     *
     * @return void
     */
    public function testHandleNoOpsForUnpersistedEloquentDevice(): void
    {
        $device = new StubDevice;

        (new UpdateDeviceTimestamp)(new DeviceAuthenticated('api', $device));

        self::assertNull($device->getAttribute('last_logged_in_at'));
    }

    /**
     * Define the test environment: in-memory sqlite connection.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

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
