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
 * @method static ?\SineMacula\Laravel\Authentication\Contracts\Identity identity()
 * @method static ?\SineMacula\Laravel\Authentication\Contracts\Principal principal()
 * @method static ?\SineMacula\Laravel\Authentication\Contracts\Device device()
 * @method static ?\SineMacula\Laravel\Authentication\Contracts\Tenant tenant()
 * @method static ?string type()
 * @method static \SineMacula\Laravel\Authentication\Jwt\JwtTokenService jwt(?string $guard = null)
 * @method static void inheritDriversFrom(\Illuminate\Auth\AuthManager $existing)
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 */
final class Auth extends IlluminateAuth
{
    /**
     * Resolve the package `AuthManager` directly from the container. Equivalent
     * to `app('auth')` but type-narrowed to the package subclass.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     *
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function manager(): AuthManager
    {
        $manager = self::getFacadeApplication()?->make('auth');

        if (!$manager instanceof AuthManager) {

            $message = 'The `auth` container binding did not resolve to an'
                . ' AuthManager instance - check that AuthServiceProvider'
                . ' is registered.';

            throw new \LogicException($message);
        }

        return $manager;
    }
}
