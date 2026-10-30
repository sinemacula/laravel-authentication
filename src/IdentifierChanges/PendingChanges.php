<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;

/**
 * The pending identifier changes as the identifier change service reads and
 * writes them: one row per identity and type, keyed by the SHA-256 digest of
 * the identity's account (see `AccountAttempts::account()`) and the type, read
 * on the write PDO, and written with single statements on the table's own
 * connection.
 *
 * A request writes its row whatever row the identity had for the type, through
 * any guard, so the newest request wins: an unconditional update by key, an
 * insert that a concurrent one cannot duplicate when there was no row, and the
 * update once more when a concurrent insert won. A confirmation and a
 * cancellation delete the row only while it still names the request they read,
 * so of two confirmations, or a confirmation and a newer request, one wins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PendingChanges
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The key of the identity's pending change of the type.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return string
     */
    public static function key(Identity $identity, string $type): string
    {
        return hash('sha256', AccountAttempts::account($identity) . "\0" . $type);
    }

    /**
     * The identity's pending change of the type as stored, read from the write
     * PDO, whatever guard requested it and whether or not it has expired; or
     * `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return ?\SineMacula\Laravel\Authentication\Models\IdentifierChange
     *
     * @throws \InvalidArgumentException
     */
    public static function find(Identity $identity, string $type): ?IdentifierChange
    {
        $change = WriteConnection::query((new IdentifierChange)->newQuery())->find(self::key($identity, $type));

        return $change instanceof IdentifierChange ? $change : null;
    }

    /**
     * The identity's pending change of the type when it was requested through
     * the guard and has not expired; otherwise `null`, as if there were none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $guard
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Models\IdentifierChange
     *
     * @throws \InvalidArgumentException
     */
    public static function live(Identity $identity, string $type, string $guard, CarbonImmutable $now): ?IdentifierChange
    {
        $change = self::find($identity, $type);

        return $change !== null && $change->guard === $guard && !self::hasExpired($change, $now) ? $change : null;
    }

    /**
     * Whether the pending change has expired: from the second its expiry names.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\IdentifierChange  $change
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    public static function hasExpired(IdentifierChange $change, CarbonImmutable $now): bool
    {
        return $change->expires_at->getTimestamp() <= $now->getTimestamp();
    }

    /**
     * Write the identity's pending change, requested through the guard, in
     * place of any it had of the type, and return the one it replaced, as read
     * before the write, or `null`.
     *
     * A change read before is updated in place, and none is inserted: inside
     * the request's transaction, MySQL's `UPDATE` of a missing key would lock
     * the gap it searched until the commit, and two requests that each insert
     * into the same gap would then deadlock. Either falls back to the other
     * when a concurrent write got there first.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\RequestedChange  $change
     * @return ?\SineMacula\Laravel\Authentication\Models\IdentifierChange
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public static function write(Identity $identity, string $guard, RequestedChange $change): ?IdentifierChange
    {
        $key      = self::key($identity, $change->type);
        $replaced = self::find($identity, $change->type);
        $model    = new IdentifierChange;
        $values   = [
            'guard'             => $guard,
            'type'              => $change->type,
            'previous'          => $change->previous,
            'previous_verified' => $change->previousVerified,
            'identifier'        => $change->identifier,
            'request_id'        => $change->requestId,
            'requested_at'      => $model->fromDateTime($change->requestedAt),
            'expires_at'        => $model->fromDateTime($change->expiresAt),
        ];

        $updated = $replaced !== null && self::table()->where('id', $key)->update($values) === 1;

        if (!$updated && self::table()->insertOrIgnore(['id' => $key, ...$values]) === 0) {
            self::table()->where('id', $key)->update($values);
        }

        return $replaced;
    }

    /**
     * Delete the pending change while it still names its request. Returns
     * whether this call deleted it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\IdentifierChange  $change
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public static function delete(IdentifierChange $change): bool
    {
        return self::table()->where('id', $change->id)->where('request_id', $change->request_id)->delete() === 1;
    }

    /**
     * Delete the pending changes of the keys (see `key()`), whatever their
     * request or the guard they were requested through, in one statement. Their
     * codes need nothing: a code is checked only against its pending change's
     * binding, which names that change's request, so without the change it
     * confirms nothing, and it is pruned once it expires.
     *
     * @param  non-empty-list<string>  $keys
     * @return void
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public static function forget(array $keys): void
    {
        self::table()->whereIn('id', $keys)->delete();
    }

    /**
     * The binding of the code that confirms the pending change of the identity:
     * bound to its guard, its new identifier and its request.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\IdentifierChange  $change
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Codes\CodeBinding
     */
    public static function binding(IdentifierChange $change, Identity $identity): CodeBinding
    {
        return CodeBinding::identifierChange($change->guard, $change->type, $change->identifier, $identity, $change->request_id);
    }

    /**
     * A query on the pending changes' table, on its own connection, for the
     * writes.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private static function table(): Builder
    {
        $model = new IdentifierChange;

        return $model->getConnection()->table($model->getTable());
    }
}
