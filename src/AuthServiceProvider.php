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
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
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

        $this->app->singleton(JwtTokenService::class, static fn (Application $app): JwtTokenService => self::buildJwtTokenService($app));
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

        // Per-guard JWT block at `auth.guards.<name>.jwt` layers over the
        // package-wide `authentication.jwt.*` defaults so multiple jwt guards
        // can have distinct secrets, audiences, or kids.
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
     * Build a `JwtTokenService` from the package config, layered with an
     * optional per-guard override block. Each JWT field is resolved
     * guard-first, falling back to `authentication.jwt.*`.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  array<string, mixed>  $guardJwtConfig
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function buildJwtTokenService(Application $app, #[\SensitiveParameter] array $guardJwtConfig = []): JwtTokenService
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
     * Resolve a string JWT config value, preferring the per-guard override and
     * falling back to the package-wide default.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @param  string  $default
     * @return string
     */
    private static function resolveJwtString(ConfigRepository $config, #[\SensitiveParameter] array $guardJwtConfig, string $key, string $default): string
    {
        if (isset($guardJwtConfig[$key]) && is_string($guardJwtConfig[$key])) {
            return $guardJwtConfig[$key];
        }

        return $config->string("authentication.jwt.{$key}", $default);
    }

    /**
     * Build a `JwtKeyring` from the package config layered with an optional
     * per-guard override. When a non-empty `keys` map is found, kid mode
     * activates and `active_kid` selects the signing key; otherwise the keyring
     * uses single-secret mode.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $algorithm
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtKeyring
     */
    private static function buildKeyring(ConfigRepository $config, #[\SensitiveParameter] array $guardJwtConfig, string $algorithm): JwtKeyring
    {
        /** @var ?array<array-key, mixed> $rawKeys */
        $rawKeys = $guardJwtConfig['keys'] ?? $config->get('authentication.jwt.keys');

        if (is_array($rawKeys) && $rawKeys !== []) {

            return JwtKeyring::fromKeyMap(
                self::coerceKeysConfig($rawKeys),
                self::resolveJwtString($config, $guardJwtConfig, 'active_kid', ''),
                $algorithm,
            );
        }

        /** @var ?string $secret */
        $secret = $guardJwtConfig['secret'] ?? $config->get('authentication.jwt.secret');

        return JwtKeyring::fromSecret(is_string($secret) ? $secret : '', $algorithm);
    }

    /**
     * Validate the raw `authentication.jwt.keys` config map and return a
     * strictly-typed `kid -> secret` array. Rejects integer-indexed entries and
     * non-string secrets before forwarding to `JwtKeyring::fromKeyMap()`.
     *
     * @param  array<array-key, mixed>  $rawKeys
     * @return array<string, string>
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private static function coerceKeysConfig(#[\SensitiveParameter] array $rawKeys): array
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
                    . ' secret - check the env var backing this entry is set.';

                throw new InvalidJwtConfigurationException($message);
            }

            $coerced[$kid] = $material;
        }

        return $coerced;
    }

    /**
     * Resolve an integer JWT config value, preferring the per-guard override
     * and falling back to the package-wide default.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @param  int  $default
     * @return int
     */
    private static function resolveJwtInteger(ConfigRepository $config, #[\SensitiveParameter] array $guardJwtConfig, string $key, int $default): int
    {
        if (isset($guardJwtConfig[$key]) && is_int($guardJwtConfig[$key])) {
            return $guardJwtConfig[$key];
        }

        return $config->integer("authentication.jwt.{$key}", $default);
    }

    /**
     * Resolve a nullable string JWT config value (`issuer` / `audience`),
     * preferring the per-guard override and falling back to the package
     * default. Empty strings are normalised to `null`.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @return ?string
     */
    private static function resolveJwtNullableString(ConfigRepository $config, #[\SensitiveParameter] array $guardJwtConfig, string $key): ?string
    {
        if (array_key_exists($key, $guardJwtConfig)) {

            $value = $guardJwtConfig[$key];

            return is_string($value) && $value !== '' ? $value : null;
        }

        /** @var ?string $value */
        $value = $config->get("authentication.jwt.{$key}");

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Resolve the container's PSR-3 logger if bound, otherwise return `null` so
     * the JWT service falls back to its `NullLogger`.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return ?\Psr\Log\LoggerInterface
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function resolveOptionalLogger(Application $app): ?LoggerInterface
    {
        if (!$app->bound(LoggerInterface::class)) {
            return null;
        }

        return $app->make(LoggerInterface::class);
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
