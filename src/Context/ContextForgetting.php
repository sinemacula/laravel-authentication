<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\AfterCommit;

/**
 * Has every resolved package guard forget the authentication context it holds
 * for a session whose proofs changed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContextForgetting
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Forget every resolved guard's context of the session now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     */
    public static function now(EloquentSession&Model $session): void
    {
        self::forgetter($session)();
    }

    /**
     * Forget every resolved guard's context of the session once the writes on
     * its connection commit, or once they roll back.
     *
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     */
    public static function onSettle(AfterCommit $afterCommit, EloquentSession&Model $session): void
    {
        $forget = self::forgetter($session);

        $afterCommit->run($session, $forget);
        $afterCommit->runIfRolledBack($session, $forget);
    }

    /**
     * The callback that has every resolved guard forget its context of the
     * session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Closure(): void
     */
    private static function forgetter(EloquentSession&Model $session): \Closure
    {
        return static function () use ($session): void {

            /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
            $auth = Container::getInstance()->make('auth');

            foreach (array_keys(Config::array('auth.guards', [])) as $name) {
                $auth->resolvedGuard((string) $name)?->forgetAuthenticationContext($session);
            }
        };
    }
}
