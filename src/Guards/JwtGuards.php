<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Contracts\Config\Repository;

/**
 * The configured `jwt` guards, for the helpers that act for every one of them:
 * a proof a change outdates (a code, a reset link) may have been issued through
 * any.
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
}
