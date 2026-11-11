<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;

/**
 * Pins authentication reads to the write connection, since a lagging replica
 * could admit a credential the primary has already rejected.
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
     * Route the builder to the write PDO. Eager loads run as separate queries
     * it does not reach, so a lookup that eager-loads also runs in `during()`.
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
     * Run the callback with model reads, and query-builder reads on an Eloquent
     * subject's own connection, routed to the write PDO.
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
     * Run the callback inside `during()` against the subject as stored, an
     * Eloquent model as a copy without its loaded relations.
     *
     * @template TSubject of object
     * @template TReturn
     *
     * @param  TSubject  $subject
     * @param  \Closure(TSubject): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    public static function stored(object $subject, \Closure $callback): mixed
    {
        $stored = $subject;

        if ($subject instanceof Model) {
            $stored = $subject->withoutRelations();

            $stored->preventsLazyLoading = false;
        }

        return self::during($stored, static fn (): mixed => $callback($stored));
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
     * Whether the connection already routes reads to the write PDO, read from
     * its own scope since Laravel exposes no getter.
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
