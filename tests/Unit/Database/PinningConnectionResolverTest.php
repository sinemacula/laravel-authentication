<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Database\PinningConnectionResolver;

/**
 * Unit tests for the connection resolver `WriteConnection::during()` installs:
 * it hands out the wrapped resolver's connections, passing each Eloquent
 * connection to the pin callback first, and delegates the default connection
 * name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PinningConnectionResolver::class)]
final class PinningConnectionResolverTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A resolved connection is pinned and then returned unchanged, for the
     * named connection and for the default one.
     *
     * @return void
     */
    public function testConnectionPinsAndReturnsTheResolvedConnection(): void
    {
        $landlord = \Mockery::mock(Connection::class);
        $default  = \Mockery::mock(Connection::class);

        $inner = \Mockery::mock(ConnectionResolverInterface::class);
        $inner->shouldReceive('connection')->once()->with('landlord')->andReturn($landlord);
        $inner->shouldReceive('connection')->once()->with(null)->andReturn($default);

        $pinned   = [];
        $resolver = new PinningConnectionResolver($inner, static function (Connection $connection) use (&$pinned): void {
            $pinned[] = $connection;
        });

        self::assertSame($landlord, $resolver->connection('landlord'));
        self::assertSame($default, $resolver->connection());
        self::assertSame([$landlord, $default], $pinned);
    }

    /**
     * A connection that is not an Eloquent `Connection` has no read mode to
     * pin, so it is returned without calling the pin callback.
     *
     * @return void
     */
    public function testConnectionReturnsOtherConnectionsWithoutPinning(): void
    {
        $other = \Mockery::mock(ConnectionInterface::class);

        $inner = \Mockery::mock(ConnectionResolverInterface::class);
        $inner->shouldReceive('connection')->once()->with('other')->andReturn($other);

        $resolver = new PinningConnectionResolver($inner, static function (): void {
            self::fail('Only an Eloquent connection should be pinned.');
        });

        self::assertSame($other, $resolver->connection('other'));
    }

    /**
     * The default connection name is read from and written to the wrapped
     * resolver.
     *
     * @return void
     */
    public function testDefaultConnectionNameIsDelegatedToTheWrappedResolver(): void
    {
        $inner = \Mockery::mock(ConnectionResolverInterface::class);
        $inner->shouldReceive('getDefaultConnection')->once()->andReturn('split');
        $inner->shouldReceive('setDefaultConnection')->once()->with('landlord');

        $resolver = new PinningConnectionResolver($inner, static function (): void {});

        self::assertSame('split', $resolver->getDefaultConnection());

        $resolver->setDefaultConnection('landlord');
    }
}
