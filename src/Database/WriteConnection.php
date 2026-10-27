<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;

/**
 * Pins authentication reads to the write connection.
 *
 * Every read that decides authentication, activity, replay, or revocation
 * (device, identity, and principal lookups) must see the primary's current
 * state. A read replica can lag behind a revocation, a deactivation, or a
 * refresh rotation, so a lookup served from it can admit a credential the
 * primary has already rejected. `query()` covers the queries the package
 * builds; `during()` covers reads made inside application code the package
 * calls (for example `resolveDefaultPrincipal()`), which the package cannot
 * rewrite. Custom identity providers and principal resolvers carry the same
 * obligation and may use either method.
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
     * Run the callback with every read on the subject's connection routed to
     * the write PDO, restoring the connection's previous read mode afterwards
     * (also when the callback throws).
     *
     * A subject that is not an Eloquent model has no connection to pin, so the
     * callback simply runs; reads it makes are then the caller's obligation.
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
        if (!$subject instanceof Model) {
            return $callback();
        }

        $connection = $subject->getConnection();
        $previous   = self::readsOnWriteConnection($connection);

        $connection->useWriteConnectionWhenReading();

        try {
            return $callback();
        } finally {
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
