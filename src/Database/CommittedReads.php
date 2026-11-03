<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Database\Connection;

/**
 * The isolation rule of the revocations that must find what is committed now
 * inside a caller's transaction: the sessions a connection or a link
 * established, which a sign-in through it may have committed while the caller's
 * transaction waited for its own lock on the connection or the link.
 *
 * On PostgreSQL at REPEATABLE READ or SERIALIZABLE every read of a transaction,
 * a locking one included, sees only the snapshot taken at its first statement,
 * so such a session is never found, never revoked, and no serialization failure
 * follows, since nothing the revocation locks was changed: the revocation would
 * fail open. It is refused there instead, before anything is read. MySQL's
 * locking reads see what is committed whatever the isolation level, and SQLite
 * has one writer at a time, so neither is asked; nor is a revocation outside a
 * caller's transaction, whose own transaction takes its snapshot at its first
 * read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CommittedReads
{
    /** @var list<string> The PostgreSQL isolation levels whose reads see what is committed when each is made. */
    private const array COMMITTED = ['read committed', 'read uncommitted'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse a caller's transaction on PostgreSQL whose reads see a snapshot
     * rather than what is committed, naming the work refused.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $work
     * @return void
     *
     * @throws \LogicException
     */
    public static function assert(Connection $connection, string $work): void
    {
        if ($connection->getDriverName() !== 'pgsql' || $connection->transactionLevel() === 0) {
            return;
        }

        if (!in_array($connection->scalar('select current_setting(\'transaction_isolation\')'), self::COMMITTED, true)) {
            throw new \LogicException(sprintf('%s must see what is committed now, so on PostgreSQL it runs at READ COMMITTED, never REPEATABLE READ or SERIALIZABLE.', $work));
        }
    }
}
