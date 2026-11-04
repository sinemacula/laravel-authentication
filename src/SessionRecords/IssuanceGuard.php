<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * The write every issuance of an access token for a session that does not write
 * the session's row itself (as a sign-in's insert and an activation's update
 * do) makes before it reads the session's proofs, and every change of the
 * session's proofs makes before the change, in the same transaction: an
 * increment of the session row's issuance sequence
 * (`getIssuanceSequenceName()`).
 *
 * Two of them on one session therefore never read its proofs past each other.
 * The later waits on the row the earlier wrote until the earlier ends, and then
 * reads what it committed; or, where its transaction reads a snapshot taken
 * before the earlier committed (PostgreSQL at REPEATABLE READ or SERIALIZABLE),
 * its write fails to serialise and its caller retries the whole transaction.
 * The row is the session's own, which every issuer already takes and which
 * comes after the caller's locks and the connection guard rows in the package's
 * lock order, so the guard adds no row lock and no new order. The current reads
 * of the proofs that follow it, the issuance's and every requirement
 * judgement's made under the row's lock, take more on MySQL and MariaDB at
 * REPEATABLE READ: their shared locks also hold the gaps on either side of the
 * session's proofs, where a proof of a new session or of a neighbouring one may
 * fall (`SessionProofs`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IssuanceGuard
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Increment the session's issuance sequence with one `UPDATE` by its key,
     * on its own connection and table, through the query builder, so no model
     * event fires, `updated_at` is left alone and the in-memory session is not
     * touched (nothing reads the value). Returns whether it wrote the row:
     * `false` when the session's row no longer exists, which each caller judges
     * for itself.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public static function write(EloquentSession&Model $session): bool
    {
        $key = $session->getKey() ?? throw new \LogicException('The issuance guard can only be written for a session that has a key.');

        return $session->getConnection()
            ->table($session->getTable())
            ->where($session->getKeyName(), $key)
            ->increment($session->getIssuanceSequenceName()) === 1;
    }

    /**
     * Write the guard of a session whose row must exist: one its issuer holds
     * locked, or one the token service is asked to issue for. A row that is
     * gone is a `LogicException`, and the issuer's transaction rolls back.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public static function hold(EloquentSession&Model $session): void
    {
        self::write($session) || throw new \LogicException('The session\'s row no longer exists, so its issuance guard cannot be written.');
    }
}
