<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Auth\Middleware\Authenticate as IlluminateAuthenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;

/**
 * Package service provider: registers the package's configuration, auth
 * manager, guard and provider drivers, sign-in collaborators and policies,
 * middleware, listener, publishing tags and console command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthenticationServiceProvider extends ServiceProvider
{
    /** @var list<string> File names of the shipped migrations, published under the `authentication-migrations` tag. */
    private const array MIGRATIONS = [
        '2026_04_06_000000_create_devices_table.php',
        '2026_04_06_000001_create_pending_sign_ins_table.php',
        '2026_04_06_000002_create_rate_limits_table.php',
    ];

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
        $this->app->singleton(AudiencePolicy::class, GuardAudiencePolicy::class);
        $this->app->singleton(IdentifierNormalisers::class);
        $this->app->singleton(AttemptLimiter::class, DatabaseAttemptLimiter::class);
        $this->app->singleton(SignInMethodManager::class);
        $this->app->singleton(AdditionalFactorPolicy::class, NeverRequireAdditionalFactor::class);
        $this->app->bind(IlluminateAuthenticate::class, Authenticate::class);
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
        $this->registerUnauthenticatedResponse();
        $this->registerPublishing();
        $this->registerCommands();
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function createJwtGuard(Application $app, string $name, array $config): JwtGuard
    {
        $providerName = $config['provider'] ?? '';

        /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
        $provider = IlluminateAuth::createUserProvider(is_string($providerName) ? $providerName : '');

        $selection = self::resolveGuardPrincipalResolver($app, $name, $config);
        $resolver  = $selection['resolver'];
        $events    = $app->make(Dispatcher::class);

        InvalidDeviceModelConfigurationException::validate(
            $app->make(ConfigRepository::class)->string('authentication.device.model', ''),
        );

        /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory $tokenFactory */
        $tokenFactory = $app->make(JwtTokenServiceFactory::class);
        $tokens       = $tokenFactory->forGuard($name);

        $exchange = new RefreshTokenExchange(
            $tokens,
            $provider,
            $app->make(ConnectionResolverInterface::class),
            static fn (): mixed => $app->bound('db.transactions') ? $app->make('db.transactions') : null,
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
            static fn (JwtGuard $guard, \Closure $timebox): SessionService => new SessionService(
                $guard,
                $timebox,
                $tokens,
                $app,
                $app->make(ConnectionResolverInterface::class),
                static fn (): mixed => $app->bound('db.transactions') ? $app->make('db.transactions') : null,
            ),
            static fn (): RefreshTokenTransport => RefreshTokenTransport::forGuard($name, $app->make(ConfigRepository::class)),
        );

        self::wireGuardRebinds($app, $guard, $selection['tracks_global']);

        return $guard;
    }

    /**
     * Resolve the effective principal resolver for the guard; the guard driver
     * and `authentication:check` both use it.
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
     * @throws \InvalidArgumentException
     */
    public static function resolveGuardPrincipalResolver(Application $app, string $name, array $config): array
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

            $resolvedType = get_debug_type($resolver);

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
     * Register the `jwt` guard driver creator against Laravel's `Auth` factory.
     *
     * @return void
     */
    protected function registerGuardDrivers(): void
    {
        IlluminateAuth::extend(
            'jwt',
            static fn (Application $app, string $name, array $config): ContextualGuard => AuthenticationServiceProvider::createJwtGuard($app, $name, $config),
        );
    }

    /**
     * Register the `DeviceAuthenticated` event listener.
     *
     * @return void
     */
    protected function registerListeners(): void
    {
        Event::listen(DeviceAuthenticated::class, RecordDeviceUsage::class);
    }

    /**
     * Register the package guards' `401` guest response with the exception
     * handler, after any render callbacks the application registered itself.
     *
     * @return void
     */
    protected function registerUnauthenticatedResponse(): void
    {
        $this->callAfterResolving(ExceptionHandler::class, static function (mixed $handler, Application $app): void {

            if (!$handler instanceof Handler) {
                return;
            }

            $handler->renderable($app->make(UnauthenticatedResponse::class));
        });
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

        $migrations = [];

        foreach (self::MIGRATIONS as $migration) {
            $migrations[__DIR__ . '/../database/migrations/' . $migration] = database_path('migrations/' . $migration);
        }

        $this->publishes($migrations, 'authentication-migrations');
    }

    /**
     * Register the package's console commands when running in the console.
     *
     * @return void
     */
    protected function registerCommands(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->commands([CheckConfigurationCommand::class]);
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
    private static function wireGuardRebinds(Application $app, AbstractGuard $guard, bool $tracksGlobalPrincipalResolver = true): void
    {
        $app->refresh('request', $guard, 'setRequest');
        $app->refresh('events', $guard, 'setDispatcher');

        if (!$tracksGlobalPrincipalResolver) {
            return;
        }

        $app->refresh(PrincipalResolver::class, $guard, 'setPrincipalResolver');
    }
}
