<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Proofs\Provenance;

/**
 * The rows a sign-in through an external provider's connection and every
 * revocation of the sessions that connection or its links established both
 * write, so the two never pass each other unseen at any isolation level.
 *
 * Session row locks alone miss a racing sign-in at PostgreSQL REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConnectionGuards
{
    /** @var int How many guard rows a connection has, one of which each of its links writes. */
    public const int SLOTS = 64;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Write the guard of the link a sign-in's provenance records, if any.
     *
     * @param  \Illuminate\Database\ConnectionInterface  $connection
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function signIn(ConnectionInterface $connection, ?Provenance $provenance): void
    {
        if ($provenance === null) {
            return;
        }

        self::link($connection, $provenance->connectionId, $provenance->linkId ?? '');
    }

    /**
     * Write the guard of the link.
     *
     * @param  \Illuminate\Database\ConnectionInterface  $connection
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function link(ConnectionInterface $connection, string $connectionId, string $linkId): void
    {
        self::write($connection, $connectionId, [self::slot($linkId)]);
    }

    /**
     * Write every guard of the connection.
     *
     * @param  \Illuminate\Database\ConnectionInterface  $connection
     * @param  string  $connectionId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function connection(ConnectionInterface $connection, string $connectionId): void
    {
        self::write($connection, $connectionId, range(0, self::SLOTS - 1));
    }

    /**
     * The slot of the link's guard among its connection's.
     *
     * @param  string  $linkId
     * @return int
     */
    public static function slot(string $linkId): int
    {
        return crc32($linkId) % self::SLOTS;
    }

    /**
     * Insert or write the connection's guards in the slots given, in order.
     *
     * @param  \Illuminate\Database\ConnectionInterface  $connection
     * @param  string  $connectionId
     * @param  list<int>  $slots
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function write(ConnectionInterface $connection, string $connectionId, array $slots): void
    {
        $rows = array_map(static fn (int $slot): array => ['connection_id' => $connectionId, 'slot' => $slot], $slots);

        $connection->table(Config::string('authentication.proofs.guards_table', 'authentication_connection_guards'))->upsert($rows, ['connection_id', 'slot'], ['slot']);
    }
}
