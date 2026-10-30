<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Delivery\DeliverySettings;

/**
 * Unit tests for the delivery queue settings: their defaults, the names they
 * accept, the key each malformed one is reported under, and whether the
 * connection they name would run a job during its dispatch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliverySettings::class)]
final class DeliverySettingsTest extends TestCase
{
    /**
     * With no `delivery` block, both settings are `null`, for the application's
     * defaults, and the default connection decides the rest.
     *
     * @return void
     */
    public function testDefaultsApplyWhenNothingIsConfigured(): void
    {
        $settings = new DeliverySettings(new Repository(['queue' => ['default' => 'sync', 'connections' => ['sync' => ['driver' => 'sync']]]]));

        self::assertNull($settings->queueConnection());
        self::assertNull($settings->queueName());
        self::assertTrue($settings->deliversSynchronously());
        self::assertFalse($settings->fallsBackToSync());
    }

    /**
     * The queue settings are names, and an empty string, as `env()` returns for
     * a variable set to nothing, means the default like `null`.
     *
     * @return void
     */
    public function testReadsTheQueueSettings(): void
    {
        $named = self::settings(['connection' => 'redis', 'name' => 'codes']);
        $empty = self::settings(['connection' => '', 'name' => '']);

        self::assertSame(['redis', 'codes'], [$named->queueConnection(), $named->queueName()]);
        self::assertSame([null, null], [$empty->queueConnection(), $empty->queueName()]);
    }

    /**
     * Rows of `[delivery queue block, message]`: settings that are not names.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedQueues(): iterable
    {
        yield from [
            'connection a number' => [['connection' => 1], 'authentication.delivery.queue.connection must be a name, or null for the default.'],
            'connection a list'   => [['connection' => ['redis']], 'authentication.delivery.queue.connection must be a name, or null for the default.'],
            'queue a boolean'     => [['name' => false], 'authentication.delivery.queue.name must be a name, or null for the default.'],
        ];
    }

    /**
     * A queue setting that is not a name fails closed, naming the key.
     *
     * @param  array<string, mixed>  $queue
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedQueues')]
    public function testRefusesMalformedQueueSettings(array $queue, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings($queue)->validate();
    }

    /**
     * Delivery is synchronous when the configured connection, or the default
     * one when none is configured, uses the `sync` driver.
     *
     * @return void
     */
    public function testTellsWhetherTheDeliveryConnectionIsSynchronous(): void
    {
        $connections = ['sync' => ['driver' => 'sync'], 'database' => ['driver' => 'database']];

        self::assertTrue(self::settings([], ['default' => 'sync', 'connections' => $connections])->deliversSynchronously());
        self::assertFalse(self::settings([], ['default' => 'database', 'connections' => $connections])->deliversSynchronously());
        self::assertFalse(self::settings(['connection' => 'database'], ['default' => 'sync', 'connections' => $connections])->deliversSynchronously());
        self::assertTrue(self::settings(['connection' => 'sync'], ['default' => 'database', 'connections' => $connections])->deliversSynchronously());
    }

    /**
     * Rows of `[delivery connection, whether it falls back to sync]` over one
     * set of connections.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideFailoverConnections(): iterable
    {
        yield from [
            'sync itself'                       => ['sync', false],
            'a worker-backed connection'        => ['database', false],
            'a failover listing sync'           => ['to_sync', true],
            'a failover listing sync later'     => ['nested', true],
            'a failover of workers only'        => ['workers', false],
            'a failover listing itself'         => ['looping', false],
            'failovers listing each other'      => ['ping', false],
            'a failover leading into a loop'    => ['entry', false],
            'a failover listing nothing'        => ['empty', false],
            'a failover of unknown or no names' => ['unknown', false],
        ];
    }

    /**
     * A `failover` delivery connection falls back to `sync` when it lists a
     * `sync` connection, directly or through other `failover` connections; a
     * connection already on the path is not followed again, and a name that is
     * not a configured connection leads nowhere.
     *
     * @param  string  $connection
     * @param  bool  $fallsBack
     * @return void
     */
    #[DataProvider('provideFailoverConnections')]
    public function testTellsWhetherTheDeliveryConnectionFallsBackToSync(string $connection, bool $fallsBack): void
    {
        $connections = [
            'sync'     => ['driver' => 'sync'],
            'database' => ['driver' => 'database'],
            'redis'    => ['driver' => 'redis'],
            'to_sync'  => ['driver' => 'failover', 'connections' => ['redis', 'sync']],
            'nested'   => ['driver' => 'failover', 'connections' => ['database', 'workers', 'looping', 'to_sync']],
            'workers'  => ['driver' => 'failover', 'connections' => ['redis', 'database']],
            'looping'  => ['driver' => 'failover', 'connections' => ['looping', 'workers']],
            'ping'     => ['driver' => 'failover', 'connections' => ['pong', 'database']],
            'pong'     => ['driver' => 'failover', 'connections' => ['ping', 'redis']],
            'entry'    => ['driver' => 'failover', 'connections' => ['ping']],
            'empty'    => ['driver' => 'failover'],
            'unknown'  => ['driver' => 'failover', 'connections' => ['missing', ['sync'], 7]],
        ];

        $settings = self::settings(['connection' => $connection], ['default' => 'sync', 'connections' => $connections]);

        self::assertSame($fallsBack, $settings->fallsBackToSync());
        self::assertSame($connection === 'sync', $settings->deliversSynchronously());
    }

    /**
     * Rows of `[delivery queue block, queue configuration]` whose delivery
     * connection is not configured.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
     */
    public static function provideUnconfiguredConnections(): iterable
    {
        yield from [
            'unknown connection named'  => [['connection' => 'redis'], ['default' => 'sync', 'connections' => ['sync' => ['driver' => 'sync']]]],
            'no default connection'     => [[], ['connections' => ['sync' => ['driver' => 'sync']]]],
            'connection without driver' => [[], ['default' => 'sync', 'connections' => ['sync' => []]]],
        ];
    }

    /**
     * A delivery connection that is not configured fails closed.
     *
     * @param  array<string, mixed>  $delivery
     * @param  array<string, mixed>  $queue
     * @return void
     */
    #[DataProvider('provideUnconfiguredConnections')]
    public function testRefusesAnUnconfiguredConnection(array $delivery, array $queue): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.delivery.queue.connection must name a connection configured in `queue.connections`, or be null for `queue.default`.');

        self::settings($delivery, $queue)->validate();
    }

    /**
     * Build the settings over a delivery queue block and a queue configuration.
     *
     * @param  array<string, mixed>  $delivery
     * @param  array<string, mixed>  $queue
     * @return \SineMacula\Laravel\Authentication\Delivery\DeliverySettings
     */
    private static function settings(array $delivery, array $queue = ['default' => 'sync', 'connections' => ['sync' => ['driver' => 'sync']]]): DeliverySettings
    {
        return new DeliverySettings(new Repository(['authentication' => ['delivery' => ['queue' => $delivery]], 'queue' => $queue]));
    }
}
