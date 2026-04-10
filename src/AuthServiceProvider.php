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
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;

/**
 * Package service provider.
 *
 * Registers configuration, the package `AuthManager` singleton, the `model`
 * user provider driver, the `jwt` and `basic` guard drivers, the default
 * principal resolver binding, the `DeviceAuthenticated` listener, and the
 * config + migration publishing tags.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class AuthServiceProvider extends ServiceProvider
{
    /**
     * Register container bindings.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/authentication.php',
            'authentication',
        );

        $this->app->singleton(PrincipalResolver::class, DefaultPrincipalResolver::class);
        $this->app->singleton(
            JwtTokenServiceFactory::class,
            static fn (Application $app): JwtTokenServiceFactory => new JwtTokenServiceFactory(
                $app,
                $app->make(ConfigRepository::class),
            ),
        );
    }

    /**
     * Bootstrap framework integrations.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->wrapAuthManager();
        $this->registerProviderDriver();
        $this->registerGuardDrivers();
        $this->registerListeners();
        $this->registerPublishing();
    }

    /**
     * Construct a `JwtGuard` from the supplied container, guard name, and
     * Laravel guard config block.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function createJwtGuard(Application $app, string $name, array $config): JwtGuard
    {
        $providerName = $config['provider'] ?? '';

        /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
        $provider = IlluminateAuth::createUserProvider(is_string($providerName) ? $providerName : '');

        $resolver = $app->make(PrincipalResolver::class);
        $events   = $app->make(Dispatcher::class);

        /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory $tokenFactory */
        $tokenFactory = $app->make(JwtTokenServiceFactory::class);
        $tokens       = $tokenFactory->forGuard($name);

        $exchange = new RefreshTokenExchange(
            $tokens,
            $app->make(ConnectionResolverInterface::class),
            $events,
            $resolver,
            $name,
        );

        $guard = new JwtGuard(
            $name,
            $provider,
            $resolver,
            $events,
            $app->make('request'),
            $app->make(Timebox::class),
            $tokens,
            $exchange,
        );

        self::wireGuardRebinds($app, $guard);

        return $guard;
    }

    /**
     * Construct a `BasicGuard` from the supplied container, guard name, and
     * Laravel guard config block. Identifier field resolves guard-first,
     * then falls back to `authentication.credentials.identifier_field`.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\Authentication\Guards\BasicGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function createBasicGuard(Application $app, string $name, array $config): BasicGuard
    {
        $providerName = $config['provider'] ?? '';

        /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
        $provider = IlluminateAuth::createUserProvider(is_string($providerName) ? $providerName : '');

        $guardIdentifierField = $config['identifier_field'] ?? null;

        $identifierField = is_string($guardIdentifierField) && $guardIdentifierField !== ''
            ? $guardIdentifierField
            : $app->make(ConfigRepository::class)
                ->string('authentication.credentials.identifier_field', 'email');

        $guard = new BasicGuard(
            $name,
            $provider,
            $app->make(PrincipalResolver::class),
            $app->make(Dispatcher::class),
            $app->make('request'),
            $app->make(Timebox::class),
            $identifierField,
        );

        self::wireGuardRebinds($app, $guard);

        return $guard;
    }

    /**
     * Replace the framework's `auth` container binding with the package
     * `AuthManager` subclass.
     *
     * Deferred to `boot()` so this extend wraps any extends registered during
     * other providers' `register()` phase, guaranteeing the package manager is
     * the outermost decorator and previously registered drivers are captured
     * via `inheritDriversFrom()`.
     *
     * @return void
     */
    protected function wrapAuthManager(): void
    {
        $this->app->extend('auth', static function (IlluminateAuthManager $existing, Application $app): AuthManager {
            $manager = new AuthManager($app);
            $manager->inheritDriversFrom($existing);

            return $manager;
        });
    }

    /**
     * Register the `model` user provider driver against Laravel's `Auth`
     * factory.
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
     * Register the `jwt` and `basic` guard driver creators against Laravel's
     * `Auth` factory.
     *
     * @return void
     */
    protected function registerGuardDrivers(): void
    {
        IlluminateAuth::extend('jwt', static fn (Application $app, string $name, array $config): ContextualGuard => AuthServiceProvider::createJwtGuard($app, $name, $config));

        IlluminateAuth::extend('basic', static fn (Application $app, string $name, array $config): ContextualGuard => AuthServiceProvider::createBasicGuard($app, $name, $config));
    }

    /**
     * Register the `DeviceAuthenticated` event listener.
     *
     * @return void
     */
    protected function registerListeners(): void
    {
        Event::listen(DeviceAuthenticated::class, UpdateDeviceTimestamp::class);
    }

    /**
     * Register the package's config and migration publishing tags.
     *
     * @return void
     */
    protected function registerPublishing(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/authentication.php' => config_path('authentication.php'),
        ], 'authentication-config');

        $this->publishes([
            __DIR__ . '/../database/migrations/2026_04_06_000000_create_devices_table.php' => database_path('migrations/2026_04_06_000000_create_devices_table.php'),
        ], 'authentication-migrations');
    }

    /**
     * Register container `refresh` hooks that propagate runtime rebinds of
     * `request`, `events`, and the `PrincipalResolver` onto the supplied guard.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @return void
     */
    private static function wireGuardRebinds(Application $app, AbstractGuard $guard): void
    {
        $app->refresh('request', $guard, 'setRequest');
        $app->refresh('events', $guard, 'setDispatcher');
        $app->refresh(PrincipalResolver::class, $guard, 'setPrincipalResolver');
    }
}
