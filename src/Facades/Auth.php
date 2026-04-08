<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Facades;

use Illuminate\Support\Facades\Auth as IlluminateAuth;
use SineMacula\Laravel\Authentication\AuthManager;

/**
 * Package `Auth` facade.
 *
 * Subclasses Laravel's framework `Auth` facade and adds `@method`
 * annotations for the contextual accessors so IDEs get full
 * autocompletion. Both this facade and the framework facade resolve
 * through the same `auth` container key, which the package service
 * provider has already replaced with the `AuthManager` subclass.
 *
 * @see \SineMacula\Laravel\Authentication\AuthManager
 *
 * @method static \SineMacula\Laravel\Authentication\Contracts\Identity|null identity()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Principal|null principal()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Device|null device()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Organization|null organization()
 * @method static string|null scope()
 * @method static void inheritDriversFrom(\Illuminate\Auth\AuthManager $existing)
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class Auth extends IlluminateAuth
{
    /**
     * Resolve the package `AuthManager` directly from the container.
     * Equivalent to `app('auth')` but type-narrowed to the package
     * subclass.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    public static function manager(): AuthManager
    {
        $manager = self::getFacadeApplication()?->make('auth');

        assert($manager instanceof AuthManager);

        return $manager;
    }
}
