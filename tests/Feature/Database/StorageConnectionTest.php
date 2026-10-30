<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Feature tests for where the package's tables live: the storage connection,
 * the counters' connection that falls back to it, a malformed setting failing
 * closed, and whether a model lives on the storage connection, compared by
 * name, a model's own or the default one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionTest extends TestCase
{
    /**
     * The storage connection is the one configured, read on each call; `null`
     * or an empty name means the default connection.
     *
     * @return void
     */
    public function testTheStorageConnectionIsTheConfiguredOne(): void
    {
        self::assertNull(StorageConnection::name());
        self::assertSame('testing', StorageConnection::resolvedName());

        config()->set('authentication.storage.connection', 'package_store');

        self::assertSame('package_store', StorageConnection::name());
        self::assertSame('package_store', StorageConnection::resolvedName());

        config()->set('authentication.storage.connection', '');

        self::assertNull(StorageConnection::name());
        self::assertSame('testing', StorageConnection::resolvedName());
    }

    /**
     * The counters live on the connection `rate_limits.connection` names, and
     * on the storage connection when it names none.
     *
     * @return void
     */
    public function testTheCountersFallBackToTheStorageConnection(): void
    {
        self::assertNull(StorageConnection::forRateLimits());

        config()->set('authentication.storage.connection', 'package_store');

        self::assertSame('package_store', StorageConnection::forRateLimits());

        config()->set('authentication.rate_limits.connection', 'counters');

        self::assertSame('counters', StorageConnection::forRateLimits());

        config()->set('authentication.rate_limits.connection', '');

        self::assertSame('package_store', StorageConnection::forRateLimits());
    }

    /**
     * Rows of `[key, value, message]`: settings that are neither a connection
     * name nor `null` or empty, and what each is refused with.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedConnections(): iterable
    {
        $storage = '`authentication.storage.connection` must be a connection name, or null or empty for the default connection.';
        $limits  = '`authentication.rate_limits.connection` must be a connection name, or null or empty for the storage connection.';

        yield from [
            'a storage list of names'     => ['storage.connection', ['package_store'], $storage],
            'a storage true'              => ['storage.connection', true, $storage],
            'a storage false'             => ['storage.connection', false, $storage],
            'a storage integer'           => ['storage.connection', 1, $storage],
            'a rate limits list of names' => ['rate_limits.connection', ['counters'], $limits],
            'a rate limits integer'       => ['rate_limits.connection', 0, $limits],
        ];
    }

    /**
     * A setting that is not a name fails closed, naming the key, instead of
     * putting the tables on another connection than the one meant; the
     * counters' connection refuses a malformed storage connection too.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedConnections')]
    public function testRefusesAConnectionThatIsNotAName(string $key, mixed $value, string $message): void
    {
        config()->set('authentication.' . $key, $value);

        try {
            StorageConnection::forRateLimits();

            self::fail('Expected the connection to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * A model lives on the storage connection when the two name the same one, a
     * model that names none counting as on the default, whichever of them names
     * it explicitly.
     *
     * @return void
     */
    public function testAModelOnTheStorageConnectionIsHeld(): void
    {
        $identity = new IntegrationIdentity;

        self::assertTrue(StorageConnection::holds($identity));
        self::assertSame('testing', StorageConnection::nameOf($identity));
        self::assertFalse(StorageConnection::holds(new SeparateConnectionDevice));
        self::assertSame(SeparateConnectionDevice::CONNECTION, StorageConnection::nameOf(new SeparateConnectionDevice));
        self::assertTrue(StorageConnection::holds((new IntegrationIdentity)->setConnection('testing')));

        config()->set('authentication.storage.connection', 'testing');

        self::assertTrue(StorageConnection::holds($identity));

        config()->set('authentication.storage.connection', SeparateConnectionDevice::CONNECTION);

        self::assertFalse(StorageConnection::holds($identity));
        self::assertTrue(StorageConnection::holds(new SeparateConnectionDevice));
        self::assertTrue(StorageConnection::holds(new Device));
    }

    /**
     * `StorageConnection` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(StorageConnection::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(StorageConnection::class, $instance);
    }
}
