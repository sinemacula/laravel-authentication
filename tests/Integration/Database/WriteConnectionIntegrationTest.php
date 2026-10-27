<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithLaggingReplica;
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
final class WriteConnectionIntegrationTest extends TestCase
{
    use InteractsWithLaggingReplica;

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
     * A subject that is not an Eloquent model has no connection to pin: the
     * callback runs, its value is returned, and reads inside it still go to the
     * replica.
     *
     * @return void
     */
    public function testDuringRunsTheCallbackUnchangedForANonModelSubject(): void
    {
        $device = $this->seedDevice();

        $found = WriteConnection::during(new \stdClass, static fn (): array => [
            'value'  => 'resolved',
            'device' => Device::query()->find($device->getKey()),
        ]);

        self::assertSame(['value' => 'resolved', 'device' => null], $found);
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
    }

    /**
     * Create the devices table on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migrateDevicesOnPrimaryAndReplica();
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
            'authenticatable_type' => 'identity',
            'authenticatable_id'   => '1',
            'os'                   => 'ios',
        ])->save();

        return $device;
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
