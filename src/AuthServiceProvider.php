<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
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
 * the default principal resolver binding, the `DeviceAuthenticated`
 * listener, and the config + migration publishing tags.
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
     * subclass while preserving any previously registered guard
     * drivers and user provider drivers, binds the default
     * `PrincipalResolver` implementation, and binds the
     * `JwtTokenService` factory wired from config.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/laravel-authentication.php',
            'laravel-authentication',
        );

        $this->app->extend('auth', static function (IlluminateAuthManager $existing, Application $app): AuthManager {
            $manager = new AuthManager($app);
            $manager->inheritDriversFrom($existing);

            return $manager;
        });

        $this->app->singleton(PrincipalResolver::class, DefaultPrincipalResolver::class);

        $this->app->singleton(JwtTokenService::class, static fn (Application $app): JwtTokenService => self::buildJwtTokenService($app->make(ConfigRepository::class)));
    }

    /**
     * Bootstrap framework integrations.
     *
     * Registers the `model` user provider driver, the `jwt` and
     * `basic` guard drivers, the `DeviceAuthenticated` listener, and
     * the publishing tags. The contextual accessors (`identity`,
     * `principal`, `device`, `organization`, `scope`, `isInternal`,
     * `isExternal`) are exposed directly on the package `AuthManager`
     * subclass — see `SineMacula\Laravel\Authentication\AuthManager`.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->registerProviderDriver();
        $this->registerGuardDrivers();
        $this->registerListeners();
        $this->registerPublishing();
    }

    /**
     * Construct a `JwtGuard` from the supplied container, guard name,
     * and Laravel guard config block. Wires the request rebind hook
     * before returning so subsequent request rebinds propagate to the
     * guard.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    public static function createJwtGuard(Application $app, string $name, array $config): JwtGuard
    {
        $providerName = $config['provider'] ?? '';

        /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
        $provider = IlluminateAuth::createUserProvider(is_string($providerName) ? $providerName : '');

        $guard = new JwtGuard(
            $name,
            $provider,
            $app->make(PrincipalResolver::class),
            $app->make(Dispatcher::class),
            $app->make('request'),
            $app->make(Timebox::class),
            $app->make(JwtTokenService::class),
            $app->make(ConnectionResolverInterface::class),
        );

        $app->refresh('request', $guard, 'setRequest');

        return $guard;
    }

    /**
     * Construct a `BasicGuard` from the supplied container, guard
     * name, and Laravel guard config block. Reads the configurable
     * identifier field from package config and wires the request
     * rebind hook before returning.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\Authentication\Guards\BasicGuard
     */
    public static function createBasicGuard(Application $app, string $name, array $config): BasicGuard
    {
        $providerName = $config['provider'] ?? '';

        /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
        $provider = IlluminateAuth::createUserProvider(is_string($providerName) ? $providerName : '');

        $repository      = $app->make(ConfigRepository::class);
        $identifierField = $repository->string('laravel-authentication.credentials.identifier_field', 'email');

        $guard = new BasicGuard(
            $name,
            $provider,
            $app->make(PrincipalResolver::class),
            $app->make(Dispatcher::class),
            $app->make('request'),
            $app->make(Timebox::class),
            $identifierField,
        );

        $app->refresh('request', $guard, 'setRequest');

        return $guard;
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
     * Laravel's `Auth` factory. Each driver delegates to a focused
     * factory method on this provider so the registration body stays
     * within the project's method-length budget.
     *
     * @return void
     */
    protected function registerGuardDrivers(): void
    {
        IlluminateAuth::extend('jwt', static fn (Application $app, string $name, array $config): ContextualGuard => AuthServiceProvider::createJwtGuard($app, $name, $config));

        IlluminateAuth::extend('basic', static fn (Application $app, string $name, array $config): ContextualGuard => AuthServiceProvider::createBasicGuard($app, $name, $config));
    }

    /**
     * Register the `DeviceAuthenticated` event listener. The listener
     * updates the bound device's `last_logged_in_at` timestamp.
     *
     * @return void
     */
    protected function registerListeners(): void
    {
        Event::listen(DeviceAuthenticated::class, UpdateDeviceTimestamp::class);
    }

    /**
     * Register the package's config and migration publishing tags so
     * consumers may publish either independently via `vendor:publish`.
     *
     * @return void
     */
    protected function registerPublishing(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/laravel-authentication.php' => config_path('laravel-authentication.php'),
        ], 'laravel-authentication-config');

        $this->publishes([
            __DIR__ . '/../database/migrations/2026_04_06_000000_create_devices_table.php' => database_path('migrations/2026_04_06_000000_create_devices_table.php'),
        ], 'laravel-authentication-migrations');
    }

    /**
     * Build a `JwtTokenService` instance from the resolved package
     * config repository. Extracted from the singleton closure so the
     * registration body stays small and the build path is unit
     * testable in isolation.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private static function buildJwtTokenService(ConfigRepository $config): JwtTokenService
    {
        /** @var string|null $secret */
        $secret = $config->get('laravel-authentication.jwt.secret');

        /** @var string|null $issuer */
        $issuer = $config->get('laravel-authentication.jwt.issuer');

        /** @var string|null $audience */
        $audience = $config->get('laravel-authentication.jwt.audience');

        return new JwtTokenService(
            $secret ?? '',
            $config->string('laravel-authentication.jwt.algorithm', 'HS256'),
            $config->integer('laravel-authentication.jwt.access_ttl_minutes', 15),
            $config->integer('laravel-authentication.jwt.refresh_ttl_minutes', 60 * 24 * 30),
            $config->integer('laravel-authentication.jwt.leeway_seconds', 30),
            $issuer   === null || $issuer === '' ? null : $issuer,
            $audience === null || $audience === '' ? null : $audience,
        );
    }
}
