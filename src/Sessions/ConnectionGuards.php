<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Proofs\Provenance;

/**
 * The rows a sign-in through an external provider's connection and every
 * revocation of the sessions that connection or one of its links established
 * both write, so the two never pass each other unseen, whatever the isolation
 * level of the caller's transaction.
 *
 * A revocation finds the sessions it ends with locking reads, which on MySQL
 * and at PostgreSQL's READ COMMITTED read what is committed now. At
 * PostgreSQL's REPEATABLE READ or SERIALIZABLE every read, a locking one
 * included, sees the snapshot the caller's transaction took at its first
 * statement, so a session a sign-in committed after that would be missed and
 * left live, and nothing either of them read or locked would tell. So each
 * connection has `SLOTS` guard rows, and each link one of them, by a hash of
 * its id: a sign-in writes its link's row before it writes anything else, a
 * link's revocation writes that row and a connection's revocation every row of
 * the connection, each before it reads a session. Whichever of two racing
 * transactions writes the row second waits for the first to end. At REPEATABLE
 * READ or SERIALIZABLE, when the first committed after the second's snapshot
 * was taken, the second then fails to serialise (SQLSTATE 40001): the error
 * propagates (inside a caller's transaction, Laravel raises it as a
 * `DeadlockException`) and the caller retries its whole transaction, which then
 * sees the session, or the revocation, it missed.
 *
 * Each write is one statement: an insert of the rows unless they exist, which
 * writes those that do (`ON CONFLICT ... DO UPDATE`, `ON DUPLICATE KEY
 * UPDATE`), so a row first written by two racing transactions is still written
 * by both, and each holds the rows exclusively until its transaction ends. The
 * rows are the package's own, written after every lock the caller took and
 * before any session row, in slot order, so the guards never invert the
 * caller's lock order or the sessions'. Links of one connection share a row
 * only when their hashes fall in the same slot, so two sign-ins through
 * different links of a connection wait for each other once in `SLOTS`, and at
 * REPEATABLE READ the later of two such overlapping ones is retried. A row
 * names no identity, link or session, so the rows are never pruned: there are
 * at most `SLOTS` per connection.
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
     * Write the guard of the link a sign-in's provenance records, when an
     * external provider established the session; a session with no provenance
     * has no connection to guard.
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
     * Write the guard of the link (the connection and the link id given).
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
     * The slot of the link's guard among its connection's, from a hash of the
     * link id's bytes.
     *
     * @param  string  $linkId
     * @return int
     */
    public static function slot(string $linkId): int
    {
        return crc32($linkId) % self::SLOTS;
    }

    /**
     * Insert the connection's guards in the slots given, in that order, unless
     * they exist, and write those that do.
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
