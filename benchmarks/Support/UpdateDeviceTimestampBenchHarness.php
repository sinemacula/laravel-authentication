<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use Tests\Unit\Stubs\StubDevice;

/**
 * Runtime benchmark fixtures for device timestamp writes.
 */
final class UpdateDeviceTimestampBenchHarness
{
    private const int WRITE_DEVICE_POOL_SIZE = 128;
    private readonly UpdateDeviceTimestamp $listener;
    private readonly StubDevice $freshDevice;

    /** @var list<\Tests\Unit\Stubs\StubDevice> */
    private array $staleDevices   = [];
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
                    'last_seen_throttle_seconds' => 60,
                ],
            ],
        ]);

        $container = new Container;
        $container->instance('config', $config);
        Facade::setFacadeApplication($container);

        $this->listener = new UpdateDeviceTimestamp;

        $this->createSchema();

        $freshDevice = new StubDevice;
        $freshDevice->forceFill([
            'os'                => 'bench-device-fresh',
            'refresh_key'       => 'bench-device-fresh',
            'last_logged_in_at' => Carbon::now(),
        ])->save();

        $this->freshDevice = $freshDevice;

        for ($index = 0; $index < self::WRITE_DEVICE_POOL_SIZE; $index++) {
            $device = new StubDevice;
            $device->forceFill([
                'os'                => 'bench-device-stale-' . $index,
                'refresh_key'       => 'bench-device-stale-' . $index,
                'last_logged_in_at' => null,
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
            $blueprint->uuid('id')->primary();
            $blueprint->string('os')->default('');
            $blueprint->string('refresh_key')->default('');
            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();
        });
    }
}
