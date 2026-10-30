<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\TestCase;

/**
 * Feature tests for finding a device of the configured model by its identifier:
 * from the write connection, its row locked when asked, without a query for an
 * identifier that cannot be a key, and only for a correctly configured model.
 * The default connection is a read/write split whose replica lags behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceLookup::class)]
final class DeviceLookupTest extends TestCase
{
    use InteractsWithDevices, InteractsWithLaggingReplica;

    /**
     * Remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A device written moments ago, which only the primary holds yet, is found,
     * as the instance of the configured model.
     *
     * @return void
     */
    public function testFindsADeviceTheReplicaHasNotSeen(): void
    {
        $device = new Device;
        $device->forceFill([...self::liveSession(), 'authenticatable_type' => 'owner', 'authenticatable_id' => '1'])->save();

        self::assertNull(DB::connection(self::REPLICA_CONNECTION)->table('devices')->where('id', $device->getKey())->first());

        $found = DeviceLookup::find($device->getKey());

        self::assertInstanceOf(Device::class, $found);
        self::assertSame($device->getKey(), $found->getKey());
    }

    /**
     * An identifier that names no device is not found; one that cannot be a key
     * of the model is rejected without a query.
     *
     * @return void
     */
    public function testUnknownAndMalformedIdentifiersFindNothing(): void
    {
        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertNull(DeviceLookup::find('0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70'));
        self::assertSame(1, $queries);

        self::assertNull(DeviceLookup::find('not-a-uuid'));
        self::assertNull(DeviceLookup::find(42));
        self::assertNull(DeviceLookup::find(null));
        self::assertSame(1, $queries);
    }

    /**
     * The locking lookup finds a device only the primary holds yet, as the
     * instance of the configured model, and rejects an identifier that cannot
     * be a key without a query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockingLookupFindsTheDeviceOnThePrimary(): void
    {
        $device = new Device;
        $device->forceFill([...self::liveSession(), 'authenticatable_type' => 'owner', 'authenticatable_id' => '1'])->save();

        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        $found = DB::transaction(static fn (): mixed => DeviceLookup::lock($device->getKey()));

        self::assertInstanceOf(Device::class, $found);
        self::assertSame([$device->getKey(), 1], [$found->getKey(), $queries]);
        self::assertNull(DeviceLookup::lock('not-a-uuid'));
        self::assertSame(1, $queries);
    }

    /**
     * The model is a new instance of the configured class, which must be an
     * Eloquent device.
     *
     * @return void
     */
    public function testTheModelIsAFreshInstanceOfTheConfiguredClass(): void
    {
        $model = DeviceLookup::model();

        self::assertInstanceOf(Device::class, $model);
        self::assertFalse($model->exists);
        self::assertNotSame($model, DeviceLookup::model());

        config()->set('authentication.device.model', \stdClass::class);

        $this->expectException(InvalidDeviceModelConfigurationException::class);

        DeviceLookup::model();
    }

    /**
     * `DeviceLookup` is a static utility; instantiation is disallowed through
     * the private constructor. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(DeviceLookup::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * Make the lagging split the default connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }
}
