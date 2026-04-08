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
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
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

        $this->app->singleton(PrincipalResolver::class, DefaultPrincipalResolver::class);

        $this->app->singleton(JwtTokenService::class, static fn (Application $app): JwtTokenService => self::buildJwtTokenService($app));
    }

    /**
     * Bootstrap framework integrations.
     *
     * Registers the `model` user provider driver, the `jwt` and
     * `basic` guard drivers, the `DeviceAuthenticated` listener, and
     * the publishing tags. The contextual accessors (`identity`,
     * `principal`, `device`, `organization`, `scope`) are exposed
     * directly on the package `AuthManager` subclass — see
     * `SineMacula\Laravel\Authentication\AuthManager`.
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

        $resolver = $app->make(PrincipalResolver::class);
        $events   = $app->make(Dispatcher::class);
        $tokens   = $app->make(JwtTokenService::class);

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

        self::wireGuardRebinds($app, $guard);

        return $guard;
    }

    /**
     * Replace the framework's `auth` container binding with the
     * package `AuthManager` subclass.
     *
     * Deferred from `register()` to `boot()` deliberately. The
     * container's `extend()` callback chain composes registration-order:
     * an extend registered later in the lifecycle wraps any extends
     * registered earlier. By running our extend during `boot()` —
     * which fires after every provider's `register()` method — we
     * guarantee the package manager is the outermost decorator,
     * which means any guard / provider drivers other packages
     * registered against the container during `register()` are still
     * captured (via `inheritDriversFrom()`), and our contextual
     * accessors are the ones consumers see when resolving `auth`.
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
     * Register the container `refresh` hooks that propagate runtime
     * rebinds of `request`, `events`, and the `PrincipalResolver` onto
     * the supplied guard. Tests that swap any of those bindings (via
     * `app()->instance(...)`, `Event::fake()`, etc.) get the new
     * reference picked up automatically by every guard the package
     * has constructed.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @return void
     */
    private static function wireGuardRebinds(Application $app, \SineMacula\Laravel\Authentication\Guards\AbstractGuard $guard): void
    {
        $app->refresh('request', $guard, 'setRequest');
        $app->refresh('events', $guard, 'setDispatcher');
        $app->refresh(PrincipalResolver::class, $guard, 'setPrincipalResolver');
    }

    /**
     * Build a `JwtTokenService` instance from the package config and
     * the container's PSR-3 logger (when bound). Extracted from the
     * singleton closure so the registration body stays small and the
     * build path is unit testable in isolation.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private static function buildJwtTokenService(Application $app): JwtTokenService
    {
        $config = $app->make(ConfigRepository::class);

        $algorithm = $config->string('laravel-authentication.jwt.algorithm', 'HS256');

        /** @var string|null $issuer */
        $issuer = $config->get('laravel-authentication.jwt.issuer');

        /** @var string|null $audience */
        $audience = $config->get('laravel-authentication.jwt.audience');

        return new JwtTokenService(
            self::buildKeyring($config, $algorithm),
            $algorithm,
            $config->integer('laravel-authentication.jwt.access_ttl_minutes', 15),
            $config->integer('laravel-authentication.jwt.refresh_ttl_minutes', 60 * 24 * 30),
            $config->integer('laravel-authentication.jwt.leeway_seconds', 30),
            $issuer   === null || $issuer === '' ? null : $issuer,
            $audience === null || $audience === '' ? null : $audience,
            self::resolveOptionalLogger($app),
        );
    }

    /**
     * Build a `JwtKeyring` from the package config. When
     * `laravel-authentication.jwt.keys` is a non-empty map, kid mode
     * is activated and `laravel-authentication.jwt.active_kid`
     * selects which kid signs new tokens. Otherwise the keyring
     * falls back to single-secret mode using
     * `laravel-authentication.jwt.secret`.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  string  $algorithm
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtKeyring
     */
    private static function buildKeyring(ConfigRepository $config, string $algorithm): JwtKeyring
    {
        /** @var array<array-key, mixed>|null $rawKeys */
        $rawKeys = $config->get('laravel-authentication.jwt.keys');

        if (is_array($rawKeys) && $rawKeys !== []) {

            return JwtKeyring::fromKeyMap(
                self::coerceKeysConfig($rawKeys),
                $config->string('laravel-authentication.jwt.active_kid', ''),
                $algorithm,
            );
        }

        /** @var string|null $secret */
        $secret = $config->get('laravel-authentication.jwt.secret');

        return JwtKeyring::fromSecret($secret ?? '', $algorithm);
    }

    /**
     * Validate the raw `laravel-authentication.jwt.keys` config map at
     * runtime and return a strictly-typed `kid → secret` array. The
     * raw config is `mixed` (Laravel's repository accepts any payload),
     * so this guard rejects integer-indexed entries (a common mistake
     * when an operator writes `['secret_a', 'secret_b']` instead of a
     * `kid → secret` map) and any non-string secret value (`null`,
     * arrays, etc.) before forwarding to `JwtKeyring::fromKeyMap()`.
     *
     * @param  array<array-key, mixed>  $rawKeys
     * @return array<string, string>
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private static function coerceKeysConfig(array $rawKeys): array
    {
        $coerced = [];

        foreach ($rawKeys as $kid => $material) {
            if (!is_string($kid) || $kid === '') {

                $message = 'JWT key map contains a non-string or empty kid in'
                    . ' `laravel-authentication.jwt.keys`. Every entry must be'
                    . ' keyed by a non-empty string kid (integer-indexed lists'
                    . ' such as `[\'secret_a\', \'secret_b\']` are rejected).';

                throw new InvalidJwtConfigurationException($message);
            }

            if (!is_string($material)) {

                $message = "JWT key '{$kid}' in `laravel-authentication.jwt.keys`"
                    . ' is not a string. Every kid must map to a non-empty string'
                    . ' secret — check the env var backing this entry is set.';

                throw new InvalidJwtConfigurationException($message);
            }

            $coerced[$kid] = $material;
        }

        return $coerced;
    }

    /**
     * Resolve the container's PSR-3 logger (`Psr\Log\LoggerInterface`)
     * if it is bound, otherwise return `null` so the JWT service
     * falls back to its `NullLogger`. Avoids hard-binding the package
     * to a logger requirement — consumers without a PSR-3 logger
     * binding still get a working JWT service, just without parse
     * failure debug traces.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return \Psr\Log\LoggerInterface|null
     */
    private static function resolveOptionalLogger(Application $app): ?\Psr\Log\LoggerInterface
    {
        if (!$app->bound(\Psr\Log\LoggerInterface::class)) {
            return null;
        }

        return $app->make(\Psr\Log\LoggerInterface::class);
    }
}
