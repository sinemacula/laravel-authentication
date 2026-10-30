<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Auth\RequestGuard;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Auth\LaravelAuthManagerSubclass;

/**
 * Another package's provider that binds `auth` to its own subclass of Laravel's
 * auth manager while registering, with a guard driver (`subclassed`) registered
 * on it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BindsLaravelAuthManagerSubclass extends ServiceProvider
{
    /**
     * Bind `auth` to the manager.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->singleton('auth', static function (Application $app): IlluminateAuthManager {

            $manager = new LaravelAuthManagerSubclass($app);
            $manager->extend('subclassed', fn (Application $app): RequestGuard => new RequestGuard(static fn (): null => null, $app->make('request')));

            return $manager;
        });
    }
}
