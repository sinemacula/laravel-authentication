<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;

/**
 * Where the package's tables live: the connection the shipped models read and
 * write, and the one the shipped migrations create the tables on, so the two
 * cannot disagree.
 *
 * Devices, pending sign-ins, one-time codes, passkeys, passkey challenges, API
 * keys and identifier changes live on `authentication.storage.connection`
 * (`null` or empty for the default connection). They are kept together because
 * a session, the completion of a pending sign-in, a password reset and an
 * identifier change each write several of them in one transaction, which two
 * connections cannot commit as one; a device model on another connection is
 * refused rather than splitting one. The attempt counters live on
 * `authentication.rate_limits.connection` when it names one, so they can stay
 * out of those transactions, and on the storage connection otherwise.
 *
 * A model takes its connection when it is built, so the settings must stay the
 * same for the life of a process: moving the tables is a deploy, with a worker
 * restart and a migration the application performs, not a runtime switch.
 * Connections are compared by name, a model's own or the default one, so no
 * connection is opened.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class StorageConnection
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The connection the package's tables live on, or `null` for the default
     * connection.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function name(): ?string
    {
        return self::read('storage.connection', 'the default connection');
    }

    /**
     * The connection the attempt counters live on: the one
     * `authentication.rate_limits.connection` names, or the storage connection.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function forRateLimits(): ?string
    {
        return self::read('rate_limits.connection', 'the storage connection') ?? self::name();
    }

    /**
     * Whether the model lives on the storage connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function holds(Model $model): bool
    {
        return self::nameOf($model) === self::resolvedName();
    }

    /**
     * The name of the model's connection: its own, or the default one.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function nameOf(Model $model): string
    {
        return $model->getConnectionName() ?? Config::string('database.default');
    }

    /**
     * The name of the storage connection: the configured one, or the default
     * one.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function resolvedName(): string
    {
        return self::name() ?? Config::string('database.default');
    }

    /**
     * Read a connection setting under `authentication`: a name, or `null` for
     * what an empty one means. Anything else fails closed rather than falling
     * back to another connection.
     *
     * @param  string  $key
     * @param  string  $fallback
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function read(string $key, string $fallback): ?string
    {
        $connection = Config::get('authentication.' . $key);

        if ($connection !== null && !is_string($connection)) {
            throw new \InvalidArgumentException(sprintf('`authentication.%s` must be a connection name, or null or empty for %s.', $key, $fallback));
        }

        return $connection === '' ? null : $connection;
    }
}
