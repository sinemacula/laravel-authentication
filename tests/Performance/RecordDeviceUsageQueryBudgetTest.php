<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\Carbon;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage;
use Tests\Concerns\InteractsWithDevices;
use Tests\Unit\Stubs\StubDevice;

/**
 * Query-budget contracts for isolated device last-use writes: the time, IP
 * address, and user agent are written in one update, and nothing is read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDeviceUsage::class)]
final class RecordDeviceUsageQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithDevices;

    /** @var string Timestamp format used by the device table columns. */
    private const string DATETIME_FORMAT = 'Y-m-d H:i:s';

    /**
     * Provision the persisted stub-device table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createDeviceTable('stub_devices');
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
        config()->set('authentication.device.last_used_throttle_seconds', 60);

        $device = $this->makePersistedDevice($this->now);

        $advanced = $this->now->copy()->addSeconds(30);
        Carbon::setTestNow($advanced);

        $listener = app(RecordDeviceUsage::class);

        $this->assertQueryBudget(0, 0, static fn () => $listener(new DeviceAuthenticated(new EventContext('api', new ClientContext('127.0.0.1', null), device: $device))));

        self::assertSame($this->now->format(self::DATETIME_FORMAT), $device->last_used_at?->format(self::DATETIME_FORMAT));
    }

    /**
     * A stale or missing last use should do exactly one update, which writes
     * the time and the client together, and no reads.
     *
     * @return void
     */
    public function testListenerForStaleTimestampUsesZeroReadsAndOneWrite(): void
    {
        config()->set('authentication.device.last_used_throttle_seconds', 60);

        $device = $this->makePersistedDevice(null);

        $advanced = $this->now->copy()->addSeconds(61);
        Carbon::setTestNow($advanced);

        $listener = app(RecordDeviceUsage::class);

        $this->assertQueryBudget(0, 1, static fn () => $listener(new DeviceAuthenticated(new EventContext('api', new ClientContext('127.0.0.1', null), device: $device))));

        self::assertSame($advanced->format(self::DATETIME_FORMAT), $device->last_used_at?->format(self::DATETIME_FORMAT));
        self::assertSame('127.0.0.1', $device->last_used_ip);
    }

    /**
     * Persist one stub device with an optional stored last-use time.
     *
     * @param  ?\Carbon\Carbon  $lastUsedAt
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function makePersistedDevice(?Carbon $lastUsedAt): StubDevice
    {
        $device = new StubDevice;
        $device->forceFill([
            'refresh_key'  => 'stub-refresh-key',
            'last_used_at' => $lastUsedAt,
        ])->save();

        return $device;
    }
}
