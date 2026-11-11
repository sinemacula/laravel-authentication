<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Sessions\ConnectionGuards;
use Tests\TestCase;

/**
 * Feature tests of the connection guards external sign-ins and connection
 * revocations write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionGuards::class)]
final class ConnectionGuardsTest extends TestCase
{
    /** @var string The guard table the shipped migration creates. */
    private const string TABLE = 'authentication_connection_guards';

    /**
     * A link's guard is in the slot the CRC-32 of its id falls in.
     *
     * @return void
     */
    public function testALinksGuardIsInTheSlotItsIdHashesTo(): void
    {
        self::assertSame(64, ConnectionGuards::SLOTS);
        self::assertSame(0, ConnectionGuards::slot(''));
        self::assertSame(26, ConnectionGuards::slot('link-1'));
        self::assertSame(32, ConnectionGuards::slot('link-2'));
        self::assertSame(54, ConnectionGuards::slot('LINK-1'));
        self::assertSame(ConnectionGuards::slot('link-3'), ConnectionGuards::slot('LINK-1'));
    }

    /**
     * A sign-in writes only the guard of its link.
     *
     * @return void
     */
    public function testASignInWritesTheGuardOfItsLinkOnly(): void
    {
        $connection = DB::connection();

        ConnectionGuards::signIn($connection, null);

        self::assertSame(0, DB::table(self::TABLE)->count());

        ConnectionGuards::signIn($connection, new Provenance('connection-7', linkId: 'link-1'));
        ConnectionGuards::signIn($connection, new Provenance('connection-8'));

        self::assertSame([['connection-7', 26], ['connection-8', 0]], self::guards());
    }

    /**
     * Writing a link's guard again keeps one row.
     *
     * @return void
     */
    public function testWritingALinksGuardAgainKeepsOneRow(): void
    {
        $connection = DB::connection();

        ConnectionGuards::link($connection, 'connection-7', 'link-1');
        ConnectionGuards::link($connection, 'connection-7', 'link-1');
        ConnectionGuards::signIn($connection, new Provenance('connection-7', linkId: 'link-1'));
        ConnectionGuards::link($connection, 'connection-7', 'link-2');

        self::assertSame([['connection-7', 26], ['connection-7', 32]], self::guards());
    }

    /**
     * A connection's revocation writes every guard of the connection.
     *
     * @return void
     */
    public function testAConnectionsRevocationWritesEveryGuardOfTheConnection(): void
    {
        $connection = DB::connection();

        ConnectionGuards::link($connection, 'connection-7', 'link-1');
        ConnectionGuards::link($connection, 'connection-8', 'link-1');
        ConnectionGuards::connection($connection, 'connection-7');
        ConnectionGuards::connection($connection, 'connection-7');

        $slots = array_map(static fn (array $guard): int => $guard[1], array_filter(self::guards(), static fn (array $guard): bool => $guard[0] === 'connection-7'));

        self::assertSame(range(0, 63), array_values($slots));
        self::assertSame(65, DB::table(self::TABLE)->count());
    }

    /**
     * The guards cannot be instantiated from outside.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ConnectionGuards::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ConnectionGuards::class, $instance);
    }

    /**
     * The guards, as `[connection id, slot]`, by connection and slot.
     *
     * @return list<array{0: string, 1: int}>
     */
    private static function guards(): array
    {
        /** @var list<\stdClass> $rows */
        $rows = DB::table(self::TABLE)->orderBy('connection_id')->orderBy('slot')->get()->all();

        return array_map(static fn (\stdClass $row): array => [(string) $row->connection_id, (int) $row->slot], $rows);
    }
}
