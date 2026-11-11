<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Runtime;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Contracts\HasGuardContext;

/**
 * Finds the context of a jwt guard by its name, for a queued job that carries
 * only the name.
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
