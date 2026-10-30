<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Model;

/**
 * The connection rule of the helpers that spend a proof together with a change
 * to an identity (a password reset, an identifier change): the proof (a code or
 * token, and an identifier change's pending row, on the storage connection, see
 * `StorageConnection`) and the identity, with a reset's "tokens valid after"
 * cutoff and devices, must be written in one transaction, so the identity must
 * live on the storage connection. Two connections cannot commit as one, and a
 * failure between their commits would leave a proof spent without its change,
 * or a change made with its proof still live. Both helpers refuse such an
 * identity before anything is counted or written.
 *
 * Connections are compared by name, the model's own or the default one, so the
 * check opens none.
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
     * Refuse a guard whose provider's configured model (see `providerModel()`)
     * does not live on the storage connection, before any identity is looked
     * up; a provider whose configuration names no model is left to `assert()`
     * on the identity it finds.
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
     * A new instance of the Eloquent model the guard's provider returns, when
     * its configuration names one (`auth.providers.<name>.model`), so the rule
     * can be checked before any identity is looked up.
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
