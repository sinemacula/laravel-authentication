<?php

declare(strict_types=1);

namespace Tests\Unit\Models;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Unit\Stubs\StubDevice;

/**
 * Unit tests for the shipped Device Eloquent model.
 *
 * Uses Orchestra Testbench with an in-memory sqlite connection and a
 * manually-created `devices` table, so the test does not transitively
 * depend on the package migration file.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class DeviceTest extends TestCase
{
    /**
     * Define the test environment: in-memory sqlite and package config
     * defaults that the Device model depends on.
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

        $config->set('laravel-authentication.device.model', Device::class);
        $config->set('laravel-authentication.device.table', 'devices');
    }

    /**
     * Set up the in-memory schema for the Device table after the
     * Testbench application is ready.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('devices', static function (Blueprint $blueprint): void {

            $blueprint->ulid('id')->primary();
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();
            $blueprint->string('os')->default('');
            $blueprint->string('refresh_key')->default('');
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
    protected function tearDown(): void
    {
        Schema::dropIfExists('devices');

        parent::tearDown();
    }

    /**
     * Asserts the Device model reads its table name from package
     * config at construction time.
     *
     * @return void
     */
    public function testReadsTableNameFromConfigOnConstruction(): void
    {
        config()->set('laravel-authentication.device.table', 'custom_devices');

        $device = new Device();

        self::assertSame('custom_devices', $device->getTable());
    }

    /**
     * Asserts the Device model populates the `id` column with a
     * 26-character ULID on insert via HasUlids.
     *
     * @return void
     */
    public function testGeneratesUlidPrimaryKeyOnInsert(): void
    {
        $device = new Device();
        $device->save();

        self::assertIsString($device->id);
        self::assertSame(26, strlen($device->id));
    }

    /**
     * Asserts `last_logged_in_at` is cast to a Carbon instance.
     *
     * @return void
     */
    public function testCastsLastLoggedInAtToCarbon(): void
    {
        $device = new Device();
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
        $device = new Device();
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
        $device = new Device();

        self::assertInstanceOf(MorphTo::class, $device->authenticatable());
    }

    /**
     * Asserts the `device.model` config key can be read back via
     * `config(...)`. The actual runtime swap is exercised by the
     * integration test in T25.
     *
     * @return void
     */
    public function testCustomDeviceClassResolvesViaConfig(): void
    {
        config()->set('laravel-authentication.device.model', StubDevice::class);

        self::assertSame(
            StubDevice::class,
            config('laravel-authentication.device.model'),
        );
    }
}
