<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Config;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Database\SharedConnection;

/**
 * The configured `jwt` guards, for the helpers that act for every one of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class JwtGuards
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The names of the guards `auth.guards` configures with the `jwt` driver,
     * in their configured order.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<string>
     */
    public static function names(Repository $config): array
    {
        $guards = $config->get('auth.guards');
        $names  = [];

        foreach (is_array($guards) ? $guards : [] as $name => $guard) {

            if (!is_array($guard) || ($guard['driver'] ?? null) !== 'jwt') {
                continue;
            }

            $names[] = (string) $name;
        }

        return $names;
    }

    /**
     * The names of the `jwt` guards whose provider can return the identity, in
     * their configured order.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  \Illuminate\Config\Repository  $config
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public static function namesFor(Model $identity, ConfigRepository $config): array
    {
        $default = $config->string('database.default');
        $reads   = static fn (Model $model): array => [$model->getConnectionName() ?? $default, $model->getTable()];
        $names   = [];

        foreach (self::names($config) as $name) {

            $model = SharedConnection::providerModel($name, $config);

            if ($model !== null && $reads($model) !== $reads($identity)) {
                continue;
            }

            $names[] = $name;
        }

        return $names;
    }
}
