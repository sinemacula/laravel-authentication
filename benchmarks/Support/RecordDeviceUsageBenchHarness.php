<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage;
use Tests\Unit\Stubs\StubDevice;

/**
 * Runtime benchmark fixtures for device last-use writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecordDeviceUsageBenchHarness
{
    /** @var int Number of mutable write-path devices to pre-seed. */
    private const int WRITE_DEVICE_POOL_SIZE = 128;

    /** @var \SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage */
    private readonly RecordDeviceUsage $listener;

    /** @var \Tests\Unit\Stubs\StubDevice */
    private readonly StubDevice $freshDevice;

    /** @var list<\Tests\Unit\Stubs\StubDevice> */
    private array $staleDevices = [];

    /** @var int Current index into the stale-device pool. */
    private int $staleDeviceIndex = 0;

    /**
     * Seed the listener benchmark fixtures.
     */
    public function __construct()
    {
        BenchDatabase::boot();

        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);
        Carbon::setTestNow($now);

        $config = new ConfigRepository([
            'authentication' => [
                'device' => [
                    'last_used_throttle_seconds' => 60,
                ],
            ],
        ]);

        $container = new Container;
        $container->instance('config', $config);
        Facade::setFacadeApplication($container);

        $this->listener = new RecordDeviceUsage(BenchRequest::client());

        $this->createSchema();

        $freshDevice = new StubDevice;
        $freshDevice->forceFill([
            ...BenchSchema::liveSession(),
            'client_name'  => 'bench-device-fresh',
            'refresh_key'  => 'bench-device-fresh',
            'last_used_at' => Carbon::now(),
        ])->save();

        $this->freshDevice = $freshDevice;

        for ($index = 0; $index < self::WRITE_DEVICE_POOL_SIZE; $index++) {

            $device = new StubDevice;
            $device->forceFill([
                ...BenchSchema::liveSession(),
                'client_name'  => 'bench-device-stale-' . $index,
                'refresh_key'  => 'bench-device-stale-' . $index,
                'last_used_at' => null,
            ])->save();

            $this->staleDevices[] = $device;
        }
    }

    /**
     * Benchmark the debounced no-op listener path.
     *
     * @return void
     */
    public function runWithinThrottleSkip(): void
    {
        ($this->listener)(new DeviceAuthenticated('api', $this->freshDevice));
    }

    /**
     * Benchmark the listener path that persists a fresh timestamp.
     *
     * @return void
     */
    public function runStaleTimestampWrite(): void
    {
        $device = $this->staleDevices[$this->staleDeviceIndex % count($this->staleDevices)];
        $this->staleDeviceIndex++;

        ($this->listener)(new DeviceAuthenticated('api', $device));
    }

    /**
     * Create the shared tables once.
     *
     * @return void
     */
    private function createSchema(): void
    {
        $schema = BenchDatabase::schema();

        if ($schema->hasTable('stub_devices')) {
            return;
        }

        $schema->create('stub_devices', static function (Blueprint $blueprint): void {
            BenchSchema::defineDeviceColumns($blueprint);
        });
    }
}
