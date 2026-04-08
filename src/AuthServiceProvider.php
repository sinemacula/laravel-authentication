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
            __DIR__ . '/../config/authentication.php',
            'authentication',
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

        // Per-guard JWT config block (if any) lives under `auth.guards.<name>.jwt`
        // and layers over the package-wide `authentication.jwt.*` defaults. This
        // lets consumers register multiple jwt guards with distinct secrets,
        // audiences, or kid rotation sets — e.g. a `staff` guard with one
        // audience and a `customer` guard with another.
        $guardJwtConfig = is_array($config['jwt'] ?? null) ? $config['jwt'] : [];

        $tokens = self::buildJwtTokenService($app, $guardJwtConfig);

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
        $identifierField = $repository->string('authentication.credentials.identifier_field', 'email');

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
            __DIR__ . '/../config/authentication.php' => config_path('authentication.php'),
        ], 'authentication-config');

        $this->publishes([
            __DIR__ . '/../database/migrations/2026_04_06_000000_create_devices_table.php' => database_path('migrations/2026_04_06_000000_create_devices_table.php'),
        ], 'authentication-migrations');
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
     * Build a `JwtTokenService` instance from the package config,
     * layered with an optional per-guard override block.
     *
     * Each JWT field (`secret`, `keys`, `active_kid`, `algorithm`,
     * TTLs, `leeway_seconds`, `issuer`, `audience`) is resolved by
     * checking the per-guard override first and falling back to the
     * package-wide `authentication.jwt.*` default. This is what lets
     * consumers register multiple jwt guards with distinct signing
     * material or audiences in a single `config/auth.php`.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  array<string, mixed>  $guardJwtConfig
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private static function buildJwtTokenService(Application $app, array $guardJwtConfig = []): JwtTokenService
    {
        $config = $app->make(ConfigRepository::class);

        $algorithm = self::resolveJwtString($config, $guardJwtConfig, 'algorithm', 'HS256');

        return new JwtTokenService(
            self::buildKeyring($config, $guardJwtConfig, $algorithm),
            $algorithm,
            self::resolveJwtInteger($config, $guardJwtConfig, 'access_ttl_minutes', 15),
            self::resolveJwtInteger($config, $guardJwtConfig, 'refresh_ttl_minutes', 60 * 24 * 30),
            self::resolveJwtInteger($config, $guardJwtConfig, 'leeway_seconds', 30),
            self::resolveJwtNullableString($config, $guardJwtConfig, 'issuer'),
            self::resolveJwtNullableString($config, $guardJwtConfig, 'audience'),
            self::resolveOptionalLogger($app),
        );
    }

    /**
     * Build a `JwtKeyring` from the package config layered with an
     * optional per-guard override block. When a non-empty `keys` map
     * is found (guard first, package second), kid mode activates and
     * the corresponding `active_kid` selects the signing key.
     * Otherwise the keyring falls back to single-secret mode using the
     * resolved `secret`.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $algorithm
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtKeyring
     */
    private static function buildKeyring(
        ConfigRepository $config,
        array $guardJwtConfig,
        string $algorithm,
    ): JwtKeyring {

        /** @var array<array-key, mixed>|null $rawKeys */
        $rawKeys = $guardJwtConfig['keys'] ?? $config->get('authentication.jwt.keys');

        if (is_array($rawKeys) && $rawKeys !== []) {

            return JwtKeyring::fromKeyMap(
                self::coerceKeysConfig($rawKeys),
                self::resolveJwtString($config, $guardJwtConfig, 'active_kid', ''),
                $algorithm,
            );
        }

        /** @var string|null $secret */
        $secret = $guardJwtConfig['secret'] ?? $config->get('authentication.jwt.secret');

        return JwtKeyring::fromSecret(is_string($secret) ? $secret : '', $algorithm);
    }

    /**
     * Resolve a string JWT config value, preferring the per-guard
     * override and falling back to the package-wide default.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @param  string  $default
     * @return string
     */
    private static function resolveJwtString(
        ConfigRepository $config,
        array $guardJwtConfig,
        string $key,
        string $default,
    ): string {

        if (isset($guardJwtConfig[$key]) && is_string($guardJwtConfig[$key])) {
            return $guardJwtConfig[$key];
        }

        return $config->string("authentication.jwt.{$key}", $default);
    }

    /**
     * Resolve an integer JWT config value, preferring the per-guard
     * override and falling back to the package-wide default.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @param  int  $default
     * @return int
     */
    private static function resolveJwtInteger(
        ConfigRepository $config,
        array $guardJwtConfig,
        string $key,
        int $default,
    ): int {

        if (isset($guardJwtConfig[$key]) && is_int($guardJwtConfig[$key])) {
            return $guardJwtConfig[$key];
        }

        return $config->integer("authentication.jwt.{$key}", $default);
    }

    /**
     * Resolve a nullable string JWT config value (`issuer` / `audience`),
     * preferring the per-guard override and falling back to the package
     * default. Empty strings are normalised to `null` so the JWT service
     * treats unset and empty configurations identically.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @return string|null
     */
    private static function resolveJwtNullableString(
        ConfigRepository $config,
        array $guardJwtConfig,
        string $key,
    ): ?string {

        if (array_key_exists($key, $guardJwtConfig)) {

            $value = $guardJwtConfig[$key];

            return is_string($value) && $value !== '' ? $value : null;
        }

        /** @var string|null $value */
        $value = $config->get("authentication.jwt.{$key}");

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Validate the raw `authentication.jwt.keys` config map at
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
                    . ' `authentication.jwt.keys`. Every entry must be'
                    . ' keyed by a non-empty string kid (integer-indexed lists'
                    . ' such as `[\'secret_a\', \'secret_b\']` are rejected).';

                throw new InvalidJwtConfigurationException($message);
            }

            if (!is_string($material)) {

                $message = "JWT key '{$kid}' in `authentication.jwt.keys`"
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
