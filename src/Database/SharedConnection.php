<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Model;

/**
 * Refuses an identity off the storage connection, since a proof and the change
 * it makes to the identity must commit in one transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SharedConnection
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse an identity that does not live on the storage connection, naming
     * the flow and both connections.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  string  $flow
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     *
     * @throws \LogicException
     */
    public static function assert(Model $identity, string $flow, Repository $config): void
    {
        $mismatch = self::mismatch($identity, $config);

        if ($mismatch !== null) {
            throw new \LogicException(sprintf('%s spends its proof with its change to the identity in one transaction, so %s', $flow, $mismatch));
        }
    }

    /**
     * Refuse a guard whose provider's configured model does not live on the
     * storage connection, before any identity is looked up.
     *
     * @param  string  $guard
     * @param  string  $flow
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     *
     * @throws \LogicException
     */
    public static function assertForGuard(string $guard, string $flow, Repository $config): void
    {
        $model = self::providerModel($guard, $config);

        if ($model === null) {
            return;
        }

        self::assert($model, $flow, $config);
    }

    /**
     * What is wrong with the identity's connection, or `null` when it is the
     * storage connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  \Illuminate\Config\Repository  $config
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function mismatch(Model $identity, Repository $config): ?string
    {
        $identities = $identity->getConnectionName() ?? $config->string('database.default');
        $storage    = StorageConnection::name()      ?? $config->string('database.default');

        if ($identities === $storage) {
            return null;
        }

        $message = '%s must be on the storage connection (`authentication.storage.connection`): the identity is on [%s],'
            . ' the package\'s tables on [%s].';

        return sprintf($message, $identity::class, $identities, $storage);
    }

    /**
     * A new instance of the Eloquent model the guard's provider configures, or
     * `null` when it names none.
     *
     * @param  string  $guard
     * @param  \Illuminate\Config\Repository  $config
     * @return ?\Illuminate\Database\Eloquent\Model
     */
    public static function providerModel(string $guard, Repository $config): ?Model
    {
        $provider = $config->get("auth.guards.{$guard}.provider");
        $class    = is_string($provider) ? $config->get("auth.providers.{$provider}.model") : null;

        return is_string($class) && is_subclass_of($class, Model::class) ? new $class : null;
    }
}
