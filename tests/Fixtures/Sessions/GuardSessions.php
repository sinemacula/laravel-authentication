<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use Illuminate\Container\Container;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Builds the session service of a JWT guard as the auth manager builds one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GuardSessions
{
    /**
     * Not instantiable: a holder of one builder.
     */
    private function __construct() {}

    /**
     * The session service of the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function of(JwtGuard $guard): SessionService
    {
        $app = Container::getInstance();

        return new SessionService(
            $guard->context(),
            $guard,
            $guard->tokens(),
            $app,
            $app->make(ConnectionResolverInterface::class),
            static fn (): mixed => $app->bound('db.transactions') ? $app->make('db.transactions') : null,
        );
    }
}
