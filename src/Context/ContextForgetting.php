<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\AfterCommit;

/**
 * Has every package guard already resolved forget the authentication context it
 * holds for a session whose proofs changed, once the change commits on the
 * session's connection, so the rest of the request builds it from the proofs as
 * they now are. A rolled-back change forgets it too: a context built inside the
 * transaction, after the change, read proofs that never committed, and must not
 * outlive them. No guard is created and no request resolved: only the guards
 * resolved under the configured names are asked.
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
     * Forget every resolved guard's context of the session once the writes on
     * its connection commit, or once they roll back.
     *
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     */
    public static function onSettle(AfterCommit $afterCommit, EloquentSession&Model $session): void
    {
        $forget = static function () use ($session): void {

            /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
            $auth = Container::getInstance()->make('auth');

            foreach (array_keys(Config::array('auth.guards', [])) as $name) {
                $auth->resolvedGuard((string) $name)?->forgetAuthenticationContext($session);
            }
        };

        $afterCommit->run($session, $forget);
        $afterCommit->runIfRolledBack($session, $forget);
    }
}
