<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Feature tests for the shipped Device Eloquent model.
 *
 * Uses Orchestra Testbench with an in-memory sqlite connection and a
 * manually-created `devices` table, so the test does not transitively depend
 * on the package migration file.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @internal
 */
#[CoversClass(Device::class)]
final class DeviceTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Set up the in-memory schema for the Device table after the Testbench
     * application is ready.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('devices', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();
            $blueprint->string('os')->default('');
            $blueprint->string('refresh_key', 64)->nullable();
            $blueprint->timestamp('revoked_at')->nullable();
            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the in-memory schema once each test has completed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('devices');

        parent::tearDown();
    }

    /**
     * Asserts that swapping `authentication.device.table` at runtime is
     * observed by the next Device instantiation. The model reads the config
     * lazily in its constructor, so no cache priming is required - tests and
     * runtime tenancy swaps pick up the new value immediately.
     *
     * @return void
     */
    public function testConstructorReadsConfiguredTableLazilyOnEachInstantiation(): void
    {
        config()->set('authentication.device.table', 'custom_devices');

        $device = new Device;

        self::assertSame('custom_devices', $device->getTable());

        // Restore the default so other tests in this class are not
        // contaminated.
        config()->set('authentication.device.table', 'devices');
    }

    /**
     * Asserts the Device model populates the `id` column with a 36-character
     * UUID v7 on insert via HasUuids.
     *
     * @return void
     */
    public function testGeneratesUuidPrimaryKeyOnInsert(): void
    {
        $device = new Device;
        $device->save();

        self::assertIsString($device->id);
        self::assertSame(36, strlen($device->id));
    }

    /**
     * Asserts `last_logged_in_at` is cast to a Carbon instance.
     *
     * @return void
     */
    public function testCastsLastLoggedInAtToCarbon(): void
    {
        $device = new Device;
        $device->forceFill(['last_logged_in_at' => '2026-04-06 12:00:00'])->save();

        $fresh = Device::query()->findOrFail($device->id);

        self::assertInstanceOf(Carbon::class, $fresh->last_logged_in_at);
    }

    /**
     * Asserts `last_mfa_verified_at` is cast to a Carbon instance.
     *
     * @return void
     */
    public function testCastsLastMfaVerifiedAtToCarbon(): void
    {
        $device = new Device;
        $device->forceFill(['last_mfa_verified_at' => '2026-04-06 12:00:00'])->save();

        $fresh = Device::query()->findOrFail($device->id);

        self::assertInstanceOf(Carbon::class, $fresh->last_mfa_verified_at);
    }

    /**
     * Asserts `authenticatable()` returns a polymorphic MorphTo relation.
     *
     * @return void
     */
    public function testAuthenticatableRelationIsMorphTo(): void
    {
        $device = new Device;

        self::assertInstanceOf(MorphTo::class, $device->authenticatable());
    }

    /**
     * Asserts the shipped model satisfies the explicit Eloquent-backed device
     * persistence boundary used by refresh rotation and last-seen writes.
     *
     * @return void
     */
    public function testImplementsEloquentDeviceContract(): void
    {
        self::assertInstanceOf(EloquentDevice::class, new Device);
    }

    /**
     * Asserts the model falls back to the literal `'devices'` table when the
     * configured table value is the empty string. The conditional collapses
     * the empty value to the default rather than letting Eloquent issue
     * queries against the empty table name.
     *
     * @return void
     */
    public function testFallsBackToDefaultTableNameWhenConfiguredValueIsEmpty(): void
    {
        config()->set('authentication.device.table', '');

        $device = new Device;

        self::assertSame('devices', $device->getTable());

        // Restore the default so other tests in this class are not
        // contaminated.
        config()->set('authentication.device.table', 'devices');
    }

    /**
     * Asserts the model falls back to `'devices'` when the Config facade
     * throws while reading `device.table`. We swap the bound config repository
     * for a Mockery stub whose `string()` method raises so the constructor's
     * catch branch is exercised. Pins the catch path in
     * `Device::resolveConfiguredTable()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testFallsBackToDefaultTableNameWhenConfigFacadeThrows(): void
    {
        $previous = $this->app?->make(ConfigRepository::class);

        $config = \Mockery::mock(ConfigRepository::class)->makePartial();
        $config->shouldReceive('string')
            ->with('authentication.device.table', 'devices')
            ->andThrow(new \RuntimeException('config repository unavailable'));

        $this->app?->instance('config', $config);
        Config::clearResolvedInstance('config');

        try {
            $device = new Device;

            self::assertSame('devices', $device->getTable());
        } finally {
            if ($previous !== null) {
                $this->app?->instance('config', $previous);
            }
            Config::clearResolvedInstance('config');
        }
    }

    /**
     * Define the test environment: in-memory sqlite and package config
     * defaults that the Device model depends on.
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

        $config->set('authentication.device.model', Device::class);
        $config->set('authentication.device.table', 'devices');
    }
}
