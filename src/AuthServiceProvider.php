<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;

/**
 * Package service provider.
 *
 * Registers configuration, the package `AuthManager` singleton, the
 * `model` user provider driver, the `jwt` and `basic` guard drivers,
 * the default principal resolver binding, the six contextual
 * `Auth::macro` accessors, the `DeviceAuthenticated` listener, and
 * the config + migration publishing tags.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class AuthServiceProvider extends ServiceProvider
{
    /**
     * Register container bindings.
     *
     * Merges the package config so consumers see defaults without
     * publishing, swaps Laravel's `auth` manager for the package
     * subclass while preserving the framework's bootstrapping, binds
     * the default `PrincipalResolver` implementation, and binds the
     * `JwtTokenService` factory wired from config.
     *
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/laravel-authentication.php',
            'laravel-authentication',
        );

        $this->app->extend(
            'auth',
            static fn (IlluminateAuthManager $existing, Application $app): AuthManager => new AuthManager($app),
        );

        $this->app->singleton(PrincipalResolver::class, DefaultPrincipalResolver::class);

        $this->app->singleton(JwtTokenService::class, static function (Application $app): JwtTokenService {

            $config = $app->make(ConfigRepository::class);

            return new JwtTokenService(
                (string) ($config->get('laravel-authentication.jwt.secret') ?? ''),
                (string) ($config->get('laravel-authentication.jwt.algorithm') ?? 'HS256'),
                (int) ($config->get('laravel-authentication.jwt.access_ttl_minutes') ?? 15),
            );
        });
    }

    /**
     * Bootstrap framework integrations.
     *
     * Registers the `model` user provider driver, the `jwt` and
     * `basic` guard drivers, the six contextual facade macros, the
     * `DeviceAuthenticated` listener, and the publishing tags.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->registerProviderDriver();
        $this->registerGuardDrivers();
        $this->registerFacadeMacros();
        $this->registerListeners();
        $this->registerPublishing();
    }

    /**
     * Register the `model` user provider driver against Laravel's
     * `Auth` factory so consumers may set
     * `auth.providers.<name>.driver = model` in `config/auth.php`.
     *
     * @return void
     */
    protected function registerProviderDriver(): void
    {
        IlluminateAuth::provider('model', static function (Application $app, array $config): IdentityProvider {

            $hasher = $app->make(Hasher::class);
            $model  = (string) ($config['model'] ?? '');

            return new ModelProvider($hasher, $model);
        });
    }

    /**
     * Register the `jwt` and `basic` guard driver creators against
     * Laravel's `Auth` factory. Each closure resolves the guard's
     * collaborators from the container and asks the framework to
     * refresh the bound `Request` whenever the application rebinds
     * one.
     *
     * @return void
     */
    protected function registerGuardDrivers(): void
    {
        IlluminateAuth::extend('jwt', static function (Application $app, string $name, array $config): ContextualGuard {

            /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
            $provider = IlluminateAuth::createUserProvider((string) ($config['provider'] ?? ''));

            $guard = new JwtGuard(
                $name,
                $provider,
                $app->make(PrincipalResolver::class),
                $app->make(Dispatcher::class),
                $app->make('request'),
                $app->make(Timebox::class),
                $app->make(JwtTokenService::class),
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });

        IlluminateAuth::extend('basic', static function (Application $app, string $name, array $config): ContextualGuard {

            /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
            $provider = IlluminateAuth::createUserProvider((string) ($config['provider'] ?? ''));

            $guard = new BasicGuard(
                $name,
                $provider,
                $app->make(PrincipalResolver::class),
                $app->make(Dispatcher::class),
                $app->make('request'),
                $app->make(Timebox::class),
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    /**
     * Register the six contextual `Auth::macro` accessors. Each macro
     * forwards to the active guard when it implements
     * `ContextualGuard`, otherwise returns the safe fallback (`null`
     * for nullable accessors, `false` for boolean accessors). Macros
     * are static closures that resolve the active guard via the
     * container so `$this`-rebinding is not required.
     *
     * @return void
     */
    protected function registerFacadeMacros(): void
    {
        IlluminateAuth::macro('principal', static function (): ?Principal {

            $guard = self::resolveActiveGuard();

            return $guard instanceof ContextualGuard ? $guard->principal() : null;
        });

        IlluminateAuth::macro('device', static function (): ?Device {

            $guard = self::resolveActiveGuard();

            return $guard instanceof ContextualGuard ? $guard->device() : null;
        });

        IlluminateAuth::macro('organization', static function (): ?Organization {

            $guard = self::resolveActiveGuard();

            return $guard instanceof ContextualGuard ? $guard->organization() : null;
        });

        IlluminateAuth::macro('scope', static function (): ?string {

            $guard = self::resolveActiveGuard();

            return $guard instanceof ContextualGuard ? $guard->scope() : null;
        });

        IlluminateAuth::macro('isInternal', static function (): bool {

            $guard = self::resolveActiveGuard();

            return $guard instanceof ContextualGuard ? $guard->isInternal() : false;
        });

        IlluminateAuth::macro('isExternal', static function (): bool {

            $guard = self::resolveActiveGuard();

            return $guard instanceof ContextualGuard ? $guard->isExternal() : false;
        });
    }

    /**
     * Resolve the active guard from the package `AuthManager`.
     *
     * Used by every contextual facade macro so the macro closures can
     * remain static and free of `$this`-rebinding tricks.
     *
     * @return \Illuminate\Contracts\Auth\Guard
     */
    private static function resolveActiveGuard(): Guard
    {
        return app('auth')->guard();
    }

    /**
     * Register the `DeviceAuthenticated` event listener. The listener
     * updates the bound device's `last_logged_in_at` timestamp.
     *
     * @return void
     */
    protected function registerListeners(): void
    {
        Event::listen(DeviceAuthenticated::class, [UpdateDeviceTimestamp::class, 'handle']);
    }

    /**
     * Register the package's config and migration publishing tags so
     * consumers may publish either independently via `vendor:publish`.
     *
     * @return void
     */
    protected function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/laravel-authentication.php' => config_path('laravel-authentication.php'),
        ], 'laravel-authentication-config');

        $this->publishes([
            __DIR__ . '/../database/migrations/2026_04_06_000000_create_devices_table.php'
                => database_path('migrations/2026_04_06_000000_create_devices_table.php'),
        ], 'laravel-authentication-migrations');
    }
}
