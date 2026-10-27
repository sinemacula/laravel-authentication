<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;

/**
 * Pins authentication reads to the write connection.
 *
 * Every read that decides authentication, activity, replay, or revocation
 * (device, identity, and principal lookups) must see the primary's current
 * state. A read replica can lag behind a revocation, a deactivation, or a
 * refresh rotation, so a lookup served from it can admit a credential the
 * primary has already rejected. `query()` routes one query the package builds;
 * `during()` covers every other read while a callback runs: the relations a
 * lookup eager-loads, which Eloquent fetches with separate queries `query()`
 * does not reach, relations on other connections (a tenant in a landlord
 * database), and reads made inside application code the package calls (for
 * example `resolveDefaultPrincipal()`), which the package cannot rewrite.
 * Custom identity providers and principal resolvers carry the same obligation
 * and use whichever method covers their reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class WriteConnection
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Route the supplied Eloquent builder, relation, or query builder to the
     * write PDO and return it for chaining.
     *
     * Only this query is routed: the eager loads of its results run as separate
     * queries without the flag, so a lookup whose model eager-loads relations
     * (`$with`, `with()`) also runs inside `during()`.
     *
     * @template TBuilder of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TBuilder  $query
     * @return TBuilder
     */
    public static function query(Builder $query): Builder
    {
        $query->useWritePdo();

        return $query;
    }

    /**
     * Run the callback with reads routed to the write PDO, restoring each
     * connection's previous read mode afterwards (also when the callback
     * throws).
     *
     * Every connection a model resolves inside the callback is pinned, so a
     * relation on another connection, eager-loaded by a lookup or lazily loaded
     * by an activity check, is read from that connection's writer. When the
     * subject is an Eloquent model, reads on its own connection are pinned as
     * well, including ones made through the query builder rather than a model.
     *
     * A subject that is not an Eloquent model (a custom principal or identity)
     * has no connection of its own, so only its model reads are pinned; a
     * query-builder or `DB` read it makes must pin itself.
     *
     * @template TReturn
     *
     * @param  object  $subject
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    public static function during(object $subject, \Closure $callback): mixed
    {
        /** @var array<int, array{0: \Illuminate\Database\Connection, 1: bool}> $pinned */
        $pinned = [];

        $pin = static function (Connection $connection) use (&$pinned): void {
            $pinned[spl_object_id($connection)] ??= [$connection, self::readsOnWriteConnection($connection)];

            $connection->useWriteConnectionWhenReading();
        };

        if ($subject instanceof Model) {
            $pin($subject->getConnection());
        }

        $resolver = Model::getConnectionResolver();

        if ($resolver !== null) {
            Model::setConnectionResolver(new PinningConnectionResolver($resolver, $pin));
        }

        try {
            return $callback();
        } finally {
            self::release($resolver, $pinned);
        }
    }

    /**
     * Reinstate the model connection resolver `during()` replaced, if any, and
     * return each pinned connection to the read mode it had before.
     *
     * @param  ?\Illuminate\Database\ConnectionResolverInterface  $resolver
     * @param  array<int, array{0: \Illuminate\Database\Connection, 1: bool}>  $pinned
     * @return void
     */
    private static function release(?ConnectionResolverInterface $resolver, array $pinned): void
    {
        if ($resolver !== null) {
            Model::setConnectionResolver($resolver);
        }

        foreach ($pinned as [$connection, $previous]) {
            $connection->useWriteConnectionWhenReading($previous);
        }
    }

    /**
     * Whether the connection already routes reads to the write PDO. Laravel
     * exposes a setter for this mode but no getter, so the flag is read from
     * the connection's own scope.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private static function readsOnWriteConnection(Connection $connection): bool
    {
        $read = \Closure::bind(
            static fn (Connection $bound): bool => $bound->readOnWriteConnection,
            null,
            Connection::class,
        );

        return $read($connection);
    }
}
