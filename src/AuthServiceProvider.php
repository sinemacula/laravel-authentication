<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration;
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
 * @copyright   2026 Sine Macula Ltd
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration
     */
    public static function createJwtGuard(Application $app, string $name, array $config): JwtGuard
    {
        $providerName = $config['provider'] ?? '';

        /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
        $provider = IlluminateAuth::createUserProvider(is_string($providerName) ? $providerName : '');

        $selection = self::resolveGuardPrincipalResolver($app, $name, $config);
        $resolver  = $selection['resolver'];
        $events    = $app->make(Dispatcher::class);

        self::assertValidDeviceModelConfiguration(
            $app->make(ConfigRepository::class)->string('authentication.device.model', ''),
        );

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

        self::wireGuardRebinds($app, $guard, $selection['tracks_global']);

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

        $selection = self::resolveGuardPrincipalResolver($app, $name, $config);

        $guard = new BasicGuard(
            $name,
            $provider,
            $selection['resolver'],
            $app->make(Dispatcher::class),
            $app->make('request'),
            $app->make(Timebox::class),
            $identifierField,
        );

        self::wireGuardRebinds($app, $guard, $selection['tracks_global']);

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
     * Resolve the effective principal resolver for the guard.
     *
     * Guards without a `principal_resolver` override track the global
     * `PrincipalResolver::class` binding and should therefore receive future
     * container refreshes. Guard-local overrides resolve once at construction
     * time and are fixed thereafter.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return array{resolver: \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver, tracks_global: bool}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function resolveGuardPrincipalResolver(Application $app, string $name, array $config): array
    {
        if (!array_key_exists('principal_resolver', $config)) {

            return [
                'resolver'      => $app->make(PrincipalResolver::class),
                'tracks_global' => true,
            ];
        }

        $abstract = $config['principal_resolver'];

        if (!is_string($abstract) || $abstract === '') {
            throw new \InvalidArgumentException("Auth guard [{$name}] principal_resolver must be a non-empty string container abstract.");
        }

        $resolver = $app->make($abstract);

        if (!$resolver instanceof PrincipalResolver) {

            $resolvedType = is_object($resolver) ? $resolver::class : get_debug_type($resolver);

            $message = "Auth guard [{$name}] principal_resolver [{$abstract}]"
                . " resolved to [{$resolvedType}] instead of ["
                . PrincipalResolver::class
                . '].';

            throw new \InvalidArgumentException($message);
        }

        return [
            'resolver'      => $resolver,
            'tracks_global' => false,
        ];
    }

    /**
     * Validate that the configured device model satisfies the explicit
     * Eloquent-backed persistence boundary required by JWT refresh and
     * last-seen flows.
     *
     * @param  string  $class
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration
     */
    private static function assertValidDeviceModelConfiguration(string $class): void
    {
        if (
            $class === ''
            || !class_exists($class)
            || !is_subclass_of($class, Model::class)
            || !is_subclass_of($class, EloquentDevice::class)
        ) {
            throw InvalidDeviceModelConfiguration::unsupported($class);
        }
    }

    /**
     * Register container `refresh` hooks that propagate runtime rebinds of
     * `request`, `events`, and optionally the global `PrincipalResolver` onto
     * the supplied guard.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  bool  $tracksGlobalPrincipalResolver
     * @return void
     */
    private static function wireGuardRebinds(
        Application $app,
        AbstractGuard $guard,
        bool $tracksGlobalPrincipalResolver = true,
    ): void {
        $app->refresh('request', $guard, 'setRequest');
        $app->refresh('events', $guard, 'setDispatcher');

        if ($tracksGlobalPrincipalResolver) {
            $app->refresh(PrincipalResolver::class, $guard, 'setPrincipalResolver');
        }
    }
}
