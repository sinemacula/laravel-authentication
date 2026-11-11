<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;

/**
 * The connection the package's tables live on, read by both the shipped models
 * and the shipped migrations.
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
     * The connection the attempt counters live on, defaulting to the storage
     * connection.
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
     * The name of the storage connection, the configured one or the default.
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
     * Read a connection setting under `authentication`, `null` when it is
     * empty.
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
