<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\Carbon;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use Tests\Unit\Stubs\StubDevice;

/**
 * Query-budget contracts for isolated device timestamp writes.
 *
 * @internal
 */
#[CoversClass(UpdateDeviceTimestamp::class)]
final class UpdateDeviceTimestampQueryBudgetTest extends PerformanceContractTestCase
{
    /**
     * Provision the persisted stub-device table.
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
     * Release the persisted stub-device table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_devices');

        parent::tearDown();
    }

    /**
     * Within the debounce window the listener should skip all SQL activity.
     *
     * @return void
     */
    public function testListenerWithinThrottleWindowUsesZeroReadsAndNoWrites(): void
    {
        config()->set('authentication.device.last_seen_throttle_seconds', 60);

        $device = $this->makePersistedDevice($this->now);

        $advanced = $this->now->copy()->addSeconds(30);
        Carbon::setTestNow($advanced);

        $listener = app(UpdateDeviceTimestamp::class);

        $this->assertQueryBudget(0, 0, static fn () => $listener(new DeviceAuthenticated('api', $device)));

        self::assertSame($this->now->format('Y-m-d H:i:s'), $device->last_logged_in_at?->format('Y-m-d H:i:s'));
    }

    /**
     * A stale or missing timestamp should do exactly one update and no reads.
     *
     * @return void
     */
    public function testListenerForStaleTimestampUsesZeroReadsAndOneWrite(): void
    {
        config()->set('authentication.device.last_seen_throttle_seconds', 60);

        $device = $this->makePersistedDevice(null);

        $advanced = $this->now->copy()->addSeconds(61);
        Carbon::setTestNow($advanced);

        $listener = app(UpdateDeviceTimestamp::class);

        $this->assertQueryBudget(0, 1, static fn () => $listener(new DeviceAuthenticated('api', $device)));

        self::assertSame($advanced->format('Y-m-d H:i:s'), $device->last_logged_in_at?->format('Y-m-d H:i:s'));
    }

    /**
     * Persist one stub device with an optional stored last-login timestamp.
     *
     * @param  ?\Carbon\Carbon  $lastLoggedInAt
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function makePersistedDevice(?Carbon $lastLoggedInAt): StubDevice
    {
        $device = new StubDevice;
        $device->forceFill([
            'os'                => 'ios',
            'refresh_key'       => 'stub-refresh-key',
            'last_logged_in_at' => $lastLoggedInAt,
        ])->save();

        return $device;
    }
}
