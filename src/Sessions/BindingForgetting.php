<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * Has every package guard already resolved forget its binding to what a
 * revocation ended, creating no guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BindingForgetting
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Have every resolved guard bound to the identity forget it, but one bound
     * to the session kept.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $kept
     * @return void
     */
    public static function identity(Identity $identity, ?Session $kept = null): void
    {
        foreach (self::resolvedGuards() as $guard) {
            $guard->forgetIdentity($identity, $kept);
        }
    }

    /**
     * Have every resolved guard bound to one of the sessions forget it.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authentication\Contracts\Session>  $sessions
     * @return void
     */
    public static function sessions(array $sessions): void
    {
        foreach (self::resolvedGuards() as $guard) {
            foreach ($sessions as $session) {
                $guard->forgetSession($session);
            }
        }
    }

    /**
     * The package guards already resolved under the configured names, in their
     * configured order.
     *
     * @return list<\SineMacula\Laravel\Authentication\Contracts\ContextualGuard&\SineMacula\Laravel\Authentication\Contracts\GuardBinding>
     */
    public static function resolvedGuards(): array
    {
        /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
        $auth   = Container::getInstance()->make('auth');
        $guards = [];

        foreach (array_keys(Config::array('auth.guards', [])) as $name) {

            $guard = $auth->resolvedGuard((string) $name);

            if ($guard === null) {
                continue;
            }

            $guards[] = $guard;
        }

        return $guards;
    }
}
