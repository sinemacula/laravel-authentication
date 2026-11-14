<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;

/**
 * Feature tests for the connections the package's tables live on.
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
     * The storage connection is the one configured; `null` or an empty name
     * means the default connection.
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
     * Settings that are not a connection name, and the message each is refused
     * with.
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
     * A setting that is not a connection name is refused, naming the key.
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
     * A model lives on the storage connection when both resolve to the same
     * connection name.
     *
     * @return void
     */
    public function testAModelOnTheStorageConnectionIsHeld(): void
    {
        $identity = new IntegrationIdentity;

        self::assertTrue(StorageConnection::holds($identity));
        self::assertSame('testing', StorageConnection::nameOf($identity));
        self::assertFalse(StorageConnection::holds(new SeparateConnectionSession));
        self::assertSame(SeparateConnectionSession::CONNECTION, StorageConnection::nameOf(new SeparateConnectionSession));
        self::assertTrue(StorageConnection::holds((new IntegrationIdentity)->setConnection('testing')));

        config()->set('authentication.storage.connection', 'testing');

        self::assertTrue(StorageConnection::holds($identity));

        config()->set('authentication.storage.connection', SeparateConnectionSession::CONNECTION);

        self::assertFalse(StorageConnection::holds($identity));
        self::assertTrue(StorageConnection::holds(new SeparateConnectionSession));
        self::assertTrue(StorageConnection::holds(new Session));
    }

    /**
     * A transaction is open on the storage connection only while one is open on
     * the connection it names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionIsOpenOnlyOnTheStorageConnection(): void
    {
        config()->set('database.connections.' . SeparateConnectionSession::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        self::assertFalse(StorageConnection::isInTransaction());

        DB::transaction(static fn () => self::assertTrue(StorageConnection::isInTransaction()));

        self::assertFalse(StorageConnection::isInTransaction());

        config()->set('authentication.storage.connection', SeparateConnectionSession::CONNECTION);

        DB::transaction(static fn () => self::assertFalse(StorageConnection::isInTransaction()));
        DB::connection(SeparateConnectionSession::CONNECTION)->transaction(static fn () => self::assertTrue(StorageConnection::isInTransaction()));
    }

    /**
     * The constructor is private.
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
