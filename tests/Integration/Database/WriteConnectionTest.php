<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\Schema\Blueprint;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\PinningConnectionResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\LandlordTenant;
use Tests\TestCase;

/**
 * Integration tests for `WriteConnection` against a read/write split connection
 * whose replica lags behind the primary.
 *
 * Each test writes a device through the split connection, so the row exists on
 * the primary only. A read that finds it was served by the write connection; a
 * read that misses it was served by the replica.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteConnection::class)]
#[CoversClass(PinningConnectionResolver::class)]
final class WriteConnectionTest extends TestCase
{
    use InteractsWithDevices, InteractsWithLaggingReplica;

    /**
     * Remove the temporary primary and replica files.
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
     * Without the helper, a lookup on the split connection is served by the
     * replica and misses a row written moments earlier; through `query()` the
     * same lookup reads the primary and finds it. The helper returns the
     * builder it was given so calls can chain.
     *
     * @return void
     */
    public function testQueryRoutesTheLookupToTheWriteConnection(): void
    {
        $device = $this->seedDevice();

        self::assertNull(Device::query()->find($device->getKey()));

        $builder = Device::query();

        self::assertSame($builder, WriteConnection::query($builder));
        self::assertInstanceOf(Device::class, $builder->find($device->getKey()));
    }

    /**
     * Reads made inside the callback go to the write connection, and the
     * connection reads from the replica again once the callback returns.
     *
     * @return void
     */
    public function testDuringRoutesReadsToTheWriteConnectionOnlyForTheCallback(): void
    {
        $device = $this->seedDevice();

        $found = WriteConnection::during(new Device, static fn (): ?Device => Device::query()->whereKey($device->getKey())->first());

        self::assertInstanceOf(Device::class, $found);
        self::assertNull(Device::query()->find($device->getKey()));
    }

    /**
     * A connection that already reads from the write PDO keeps doing so after
     * the callback, rather than being reset to the replica.
     *
     * @return void
     */
    public function testDuringKeepsAConnectionThatAlreadyReadsFromTheWriter(): void
    {
        $device = $this->seedDevice();

        $this->splitConnection()->useWriteConnectionWhenReading();

        WriteConnection::during(new Device, static fn (): null => null);

        self::assertInstanceOf(Device::class, Device::query()->find($device->getKey()));
    }

    /**
     * The previous read mode is restored when a lookup inside the callback
     * throws, and the exception reaches the caller.
     *
     * @return void
     */
    public function testDuringRestoresTheReadModeWhenTheCallbackThrows(): void
    {
        $device = $this->seedDevice();

        try {
            WriteConnection::during(new Device, static fn (): Device => Device::query()->whereKey('missing')->firstOrFail());

            self::fail('The lookup inside the callback should have thrown.');
        } catch (ModelNotFoundException $exception) {
            self::assertSame(Device::class, $exception->getModel());
        }

        self::assertNull(Device::query()->find($device->getKey()));
    }

    /**
     * A model on another connection that is read inside the callback (a tenant
     * in a landlord database, say) is read from that connection's writer too,
     * and that connection reads from its replica again once the callback
     * returns.
     *
     * @return void
     */
    public function testDuringPinsAnotherConnectionAModelResolvesInsideTheCallback(): void
    {
        $tenant = $this->seedLandlordTenant();

        $found = WriteConnection::during(new Device, static fn (): ?LandlordTenant => LandlordTenant::query()->whereKey($tenant->getKey())->first());

        self::assertInstanceOf(LandlordTenant::class, $found);
        self::assertNull(LandlordTenant::query()->find($tenant->getKey()));
    }

    /**
     * The model connection resolver is swapped only for the callback: inside it
     * Eloquent resolves connections through the pinning resolver, and the
     * original resolver is back afterwards, also when the callback throws.
     *
     * @return void
     */
    public function testDuringReinstatesTheModelConnectionResolver(): void
    {
        $resolver = Model::getConnectionResolver();

        $inside = WriteConnection::during(new Device, static fn (): ?ConnectionResolverInterface => Model::getConnectionResolver());

        self::assertInstanceOf(PinningConnectionResolver::class, $inside);
        self::assertSame($resolver, Model::getConnectionResolver());

        try {
            WriteConnection::during(new Device, static fn (): Device => Device::query()->whereKey('missing')->firstOrFail());

            self::fail('The lookup inside the callback should have thrown.');
        } catch (ModelNotFoundException) {
            self::assertSame($resolver, Model::getConnectionResolver());
        }
    }

    /**
     * A nested `during()` leaves the outer pin in place: reads after the inner
     * callback returns still go to the write connection until the outer one
     * does.
     *
     * @return void
     */
    public function testNestedDuringKeepsTheOuterPin(): void
    {
        $device = $this->seedDevice();

        $found = WriteConnection::during(new Device, static function () use ($device): ?Device {

            WriteConnection::during(new Device, static fn (): ?Device => Device::query()->whereKey($device->getKey())->first());

            return Device::query()->whereKey($device->getKey())->first();
        });

        self::assertInstanceOf(Device::class, $found);
        self::assertNull(Device::query()->find($device->getKey()));
    }

    /**
     * Without a model connection resolver to wrap, the subject's own connection
     * is still pinned for the callback and restored afterwards, and no resolver
     * is installed.
     *
     * @return void
     */
    public function testDuringPinsTheSubjectsConnectionWithoutAModelConnectionResolver(): void
    {
        $device     = $this->seedDevice();
        $connection = $this->splitConnection();
        $resolver   = Model::getConnectionResolver();

        $subject = \Mockery::mock(Device::class)->makePartial();
        $subject->shouldReceive('getConnection')->andReturn($connection);

        Model::unsetConnectionResolver();

        try {
            $found = WriteConnection::during($subject, static fn (): ?object => $connection->table('devices')->where('id', $device->getKey())->first());

            self::assertNull(Model::getConnectionResolver());
        } finally {
            Model::setConnectionResolver($resolver);
        }

        self::assertNotNull($found);
        self::assertNull($connection->table('devices')->where('id', $device->getKey())->first());
    }

    /**
     * A subject that is not an Eloquent model has no connection of its own, so
     * a query-builder read made before any model read still goes to the
     * replica, but model reads inside the callback go to the writer, and the
     * connection reads from the replica again once the callback returns.
     *
     * @return void
     */
    public function testDuringPinsModelReadsForANonModelSubject(): void
    {
        $device     = $this->seedDevice();
        $connection = $this->splitConnection();

        $found = WriteConnection::during(new \stdClass, static fn (): array => [
            'row'    => $connection->table('devices')->where('id', $device->getKey())->first(),
            'device' => Device::query()->find($device->getKey()),
        ]);

        self::assertNull($found['row']);
        self::assertInstanceOf(Device::class, $found['device']);
        self::assertNull(Device::query()->find($device->getKey()));
    }

    /**
     * `WriteConnection` is a static utility; instantiation is disallowed via
     * the private constructor so consumers cannot create a stateful
     * write-connection helper. Reflection invokes the private constructor so
     * the line is covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(WriteConnection::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(WriteConnection::class, $instance);
    }

    /**
     * Use the lagging split connection as the default connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
        $this->configureLaggingLandlordReplica(app(ConfigRepository::class));
    }

    /**
     * Create the package tables on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Write a device through the split connection, so it exists on the primary
     * only.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => 'identity',
            'authenticatable_id'   => '1',
        ])->save();

        return $device;
    }

    /**
     * Write an active tenant through the landlord split connection, so it
     * exists on the landlord primary only.
     *
     * @return \Tests\Integration\Fixtures\LandlordTenant
     */
    private function seedLandlordTenant(): LandlordTenant
    {
        $this->createOnPrimaryAndReplica('landlord_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        }, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);

        $tenant = new LandlordTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        return $tenant;
    }

    /**
     * Resolve the split connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function splitConnection(): Connection
    {
        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager = app(DatabaseManager::class);

        return $manager->connection(self::SPLIT_CONNECTION);
    }
}
