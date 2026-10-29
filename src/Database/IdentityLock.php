<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Database\Eloquent\Model;

/**
 * The lock order of every transaction that writes an identity together with the
 * proofs bound to it (its codes, reset tokens and pending identifier changes):
 * the identity's own row first, then the proofs.
 *
 * A password write locks the row with its `UPDATE` before it invalidates the
 * proofs the new password outdates and ends the sessions, cancelling the
 * pending changes. A password reset, an identifier change request, confirmation
 * and cancellation would otherwise lock a proof first (the token or code they
 * spend or invalidate, the pending change they write or delete) and the other
 * proof or the identity last, so two of them racing on one identity could each
 * wait on the other until the database aborted one. Each takes this lock when
 * its transaction starts, so the second to come waits for the first to commit
 * and then finds what it left.
 *
 * The row is read `FOR UPDATE` by key, without scopes or eager loads, on the
 * identity's own connection, which is the transaction's; a database without row
 * locks (SQLite) serialises its writers anyway. It is returned as stored, so a
 * flow decides who may act on what the row says under the lock, not on the
 * instance its caller read before (a deactivation committed in between counts).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentityLock
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Lock the identity's row until the transaction around the call ends, and
     * return it as stored, or `null` when it is no longer stored.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  TModel  $identity
     * @return ?TModel
     *
     * @imperative
     */
    public static function acquire(Model $identity): ?Model
    {
        return $identity->newModelQuery()->whereKey($identity->getKey())->lockForUpdate()->first();
    }
}
