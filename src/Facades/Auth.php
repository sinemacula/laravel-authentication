<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Facades;

use Illuminate\Support\Facades\Auth as IlluminateAuth;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Package `Auth` facade.
 *
 * Subclasses Laravel's framework `Auth` facade and adds `@method` annotations
 * for the contextual accessors so IDEs get full autocompletion. Both this
 * facade and the framework facade resolve through the same `auth` container
 * key, which the package service provider has already replaced with the
 * `AuthManager` subclass.
 *
 * @see \SineMacula\Laravel\Authentication\AuthManager
 *
 * @method static Identity|null identity()
 * @method static Principal|null principal()
 * @method static Device|null device()
 * @method static Tenant|null tenant()
 * @method static string|null type()
 * @method static void inheritDriversFrom(\Illuminate\Auth\AuthManager $existing)
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class Auth extends IlluminateAuth
{
    /**
     * Resolve the package `AuthManager` directly from the container. Equivalent
     * to `app('auth')` but type-narrowed to the package subclass.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function manager(): AuthManager
    {
        $manager = self::getFacadeApplication()?->make('auth');

        assert($manager instanceof AuthManager);

        return $manager;
    }
}
