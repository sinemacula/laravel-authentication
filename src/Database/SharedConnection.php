<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;

/**
 * The connection rule of the helpers that spend a proof together with a change
 * to an identity (a password reset, an identifier change): the proof (a code or
 * token, and an identifier change's pending row, on the device model's
 * connection) and the identity, with a reset's "tokens valid after" cutoff and
 * devices, must be written in one transaction, so the identity must live on the
 * device model's connection. Two connections cannot commit as one, and a
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
     * Refuse an identity that does not live on the device model's connection,
     * naming the flow and both connections.
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
     * What is wrong with the identity's connection, or `null` when it is the
     * device model's.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  \Illuminate\Config\Repository  $config
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function mismatch(Model $identity, Repository $config): ?string
    {
        $identities = self::name($identity, $config);
        $devices    = self::name(DeviceLookup::model(), $config);

        if ($identities === $devices) {
            return null;
        }

        return sprintf('%s must be on the device model\'s connection: the identity is on [%s], the devices on [%s].', $identity::class, $identities, $devices);
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

    /**
     * The name of the model's connection: its own, or the default one.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \Illuminate\Config\Repository  $config
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function name(Model $model, Repository $config): string
    {
        return $model->getConnectionName() ?? $config->string('database.default');
    }
}
