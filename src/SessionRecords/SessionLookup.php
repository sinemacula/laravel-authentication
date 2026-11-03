<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException;

/**
 * Finds a session of the configured session model by its identifier, the way
 * the refresh exchange and the session service read a session named by a token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionLookup
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Return a new instance of the configured session model, which must satisfy
     * the Eloquent-backed `EloquentSession` boundary and live on the storage
     * connection, where the sessions it holds are written with the package's
     * other rows in one transaction.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function model(): EloquentSession&Model
    {
        $class = Config::string('authentication.session.model', '');

        InvalidSessionModelConfigurationException::validate($class);

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $model */
        $model = new $class;

        self::assertOnStorage($model);

        return $model;
    }

    /**
     * Refuse a session model that does not live on the storage connection,
     * where the package writes its sessions with its other rows in one
     * transaction, naming both connections.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function assertOnStorage(EloquentSession&Model $model): void
    {
        if (!StorageConnection::holds($model)) {
            throw InvalidSessionModelConfigurationException::offStorage($model::class, StorageConnection::nameOf($model), StorageConnection::resolvedName());
        }
    }

    /**
     * Look a session up by its identifier, reading from the write connection so
     * a lagging replica cannot serve a stale digest or revocation state. The
     * lookup runs inside `WriteConnection::during()` for the session model, so
     * relations the session model eager-loads come from the writer too.
     *
     * An identifier that cannot be a key of the session model names no session
     * and is rejected without a query; database errors on a well-formed
     * identifier propagate.
     *
     * @param  mixed  $id
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function find(mixed $id): (EloquentSession&Model)|null
    {
        return self::lookup($id, static fn (Builder $query): Builder => $query);
    }

    /**
     * Look a session up as `find()` does, and lock its row until the
     * transaction around the call ends, so a revocation of it waits for that
     * transaction, and one committed before is seen.
     *
     * @param  mixed  $id
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function lock(mixed $id): (EloquentSession&Model)|null
    {
        return self::lookup($id, static fn (Builder $query): Builder => $query->lockForUpdate());
    }

    /**
     * Read the session on the write connection through the query the callback
     * makes of the session model's, once the identifier has the shape of its
     * key.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $id
     * @param  \Closure(\Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>): \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $scope
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function lookup(mixed $id, \Closure $scope): (EloquentSession&Model)|null
    {
        $model = self::model();

        if (!SessionKeyShape::matches($model, $id)) {
            return null;
        }

        $session = WriteConnection::during($model, static fn (): mixed => $scope(WriteConnection::query($model->newQuery()))->find($id));

        return $session instanceof Model ? $session : null;
    }
}
