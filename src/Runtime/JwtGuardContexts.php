<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Runtime;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Contracts\HasGuardContext;

/**
 * Finds the context of a jwt guard by its name, for a queued job that carries
 * only the name and runs where the guard is resolved again.
 *
 * The guard is resolved first, so an undefined one keeps Laravel's refusal. It
 * must be one `auth.guards` configures with the `jwt` driver (see
 * `Config\JwtGuards`): an `InvalidArgumentException` otherwise. It must also
 * have a context (see `Contracts\HasGuardContext`), which a `jwt` driver the
 * application replaced with a guard that is not the package's does not: a
 * `LogicException` then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class JwtGuardContexts
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The context of the named jwt guard; `$delivers` says what the job sends,
     * for the refusal.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $name
     * @param  string  $delivers
     * @return \SineMacula\Laravel\Authentication\Runtime\GuardContext
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function named(Container $container, string $name, string $delivers): GuardContext
    {
        $guard = $container->make('auth')->guard($name);

        if (!in_array($name, JwtGuards::names($container->make(Repository::class)), true)) {
            throw new \InvalidArgumentException(sprintf('Auth guard [%s] is not a jwt guard, so it sends no %s.', $name, $delivers));
        }

        if (!$guard instanceof HasGuardContext) {
            throw new \LogicException(sprintf('Auth guard [%s] has the jwt driver but resolves to %s, not a package guard, so it sends no %s.', $name, $guard::class, $delivers));
        }

        return $guard->context();
    }
}
