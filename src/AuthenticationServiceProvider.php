<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\Middleware\Authenticate as IlluminateAuthenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\Codes\RefuseFactorCodes;
use SineMacula\Laravel\Authentication\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Authentication\Console\ConfigurationChecks;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\GuardAuthenticationContexts;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContexts;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use SineMacula\Laravel\Authentication\Http\Middleware\NoStore;
use SineMacula\Laravel\Authentication\Http\Middleware\UsePendingCredential;
use SineMacula\Laravel\Authentication\Http\Middleware\UseRefreshCredential;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Listeners\ForgetGuardStateBeforeJob;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use SineMacula\Laravel\Authentication\Listeners\TrackCredentialAttempts;
use SineMacula\Laravel\Authentication\Passkeys\NoPasskeyFactors;
use SineMacula\Laravel\Authentication\Passkeys\WebAuthn;
use SineMacula\Laravel\Authentication\Passwords\NoBreachedPasswordCheck;
use SineMacula\Laravel\Authentication\Passwords\NotifyingResetLinkSender;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Scopes\AcceptAnyScope;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;

/**
 * Registers the package's bindings, auth manager, guard and provider drivers,
 * middleware, listeners and publishing tags.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthenticationServiceProvider extends ServiceProvider
{
    /** @var array<class-string, class-string> Each bindable contract's default. */
    private const array DEFAULTS = [
        PrincipalResolver::class          => DefaultPrincipalResolver::class,
        ApplicationPolicy::class          => GuardApplicationPolicy::class,
        ApplicationAccess::class          => AdmitAnyPrincipal::class,
        TenantAccess::class               => OwnTenantOnly::class,
        TenantResolver::class             => ResolveNoTenant::class,
        AttemptLimiter::class             => DatabaseAttemptLimiter::class,
        AdditionalFactorPolicy::class     => NeverRequireAdditionalFactor::class,
        PasskeyFactorGate::class          => NoPasskeyFactors::class,
        TenantAuthenticationPolicy::class => RequireNothingOfTenants::class,
        ExternalIdentityLinks::class      => NoExternalLinks::class,
        RequirementCheck::class           => MeetNoRequirement::class,
        ExternalEvidencePolicy::class     => InsufficientEvidence::class,
        FactorCodeCounters::class         => RefuseFactorCodes::class,
        FreshnessPolicy::class            => ConfiguredFreshness::class,
        ScopeRegistry::class              => AcceptAnyScope::class,
        BreachedPasswordChecker::class    => NoBreachedPasswordCheck::class,
        PasswordResetLinkSender::class    => NotifyingResetLinkSender::class,
        AuthenticationContexts::class     => GuardAuthenticationContexts::class,
    ];

    /** @var list<string> The shipped migrations, published under `authentication-migrations`. */
    private const array MIGRATIONS = [
        '2026_04_06_000000_create_authentication_sessions_table.php',
        '2026_04_06_000002_create_rate_limits_table.php',
        '2026_04_06_000003_create_one_time_codes_table.php',
        '2026_04_06_000004_create_passkeys_table.php',
        '2026_04_06_000005_create_passkey_challenges_table.php',
        '2026_04_06_000006_create_api_keys_table.php',
        '2026_04_06_000007_create_identifier_changes_table.php',
        '2026_04_06_000008_create_authentication_proofs_table.php',
        '2026_04_06_000009_create_authentication_provenance_table.php',
    ];

    /**
     * Register the package's default container bindings.
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

        // Laravel's own resolution of a class bound by name, kept protected
        $resolve = \Closure::bind(
            static fn (Container $container, string $class, array $parameters): object => $container->resolve($class, $parameters, raiseEvents: false),
            null,
            Container::class,
        );

        foreach (self::DEFAULTS as $contract => $default) {
            $this->app->singletonIf($contract, static fn (Container $app, array $parameters = []): object => $resolve($app, $default, $parameters));
        }

        $this->app->singletonIf(IdentifierNormalizers::class);
        $this->app->singletonIf(SignInMethodManager::class);
        $this->app->scopedIf(Rehashing::class);
        $this->app->scopedIf(KeptSessions::class);
        $this->app->scopedIf(RequiredWork::class);
        $this->app->scopedIf(WatchedSessions::class);
        $this->app->singletonIf(WebAuthn::class);
        $this->app->singletonIf(ContextContributors::class);
        $this->app->singletonIf(ConfigurationChecks::class);
        $this->app->bindIf(IlluminateAuthenticate::class, Authenticate::class);
        $this->app->singletonIf(
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
        $this->ownAuthManager();
        $this->registerProviderDriver();
        $this->registerGuardDrivers();
        $this->registerListeners();
        $this->registerUnauthenticatedResponse();
        $this->registerMiddleware($this->app->make(Router::class));
        $this->registerPublishing();
        $this->registerCommands();
    }

    /**
     * Whether the contract still resolves to the package's own default.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $contract
     * @return bool
     */
    public static function isPackageDefault(Container $container, string $contract): bool
    {
        $default  = self::DEFAULTS[$contract]                        ?? null;
        $concrete = $container->getBindings()[$contract]['concrete'] ?? null;

        if ($default === null || !$concrete instanceof \Closure || $container->isAlias($contract)) {
            return false;
        }

        if ((new \ReflectionFunction($concrete))->getClosureScopeClass()?->getName() !== self::class) {
            return false;
        }

        // Laravel offers no public read of a binding's instance or extenders
        $read = static fn (Container $container): array => [$container->instances[$contract] ?? null, $container->extenders[$contract] ?? []];

        [$held, $extenders] = \Closure::bind($read, null, Container::class)($container);

        return $extenders === [] && ($held === null || get_debug_type($held) === $default);
    }

    /**
     * Construct a `JwtGuard`, failing here rather than on the first request
     * when the session model is misconfigured.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function createJwtGuard(Application $app, string $name, array $config): JwtGuard
    {
        $providerName = $config['provider'] ?? '';

        /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
        $provider = IlluminateAuth::createUserProvider(is_string($providerName) ? $providerName : '');

        $selection = self::resolveGuardPrincipalResolver($app, $name, $config);
        $resolver  = $selection['resolver'];
        $events    = $app->make(Dispatcher::class);

        SessionLookup::model();

        /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory $tokenFactory */
        $tokenFactory = $app->make(JwtTokenServiceFactory::class);

        $guard = new JwtGuard(
            $name,
            $provider,
            $resolver,
            $events,
            $app->make('request'),
            $app->make(Timebox::class),
            $tokenFactory->forGuard($name),
            static fn (GuardContext $context): SessionRevocations => SessionRevocations::forContext($context, $app),
            static fn (): RefreshTokenTransport => RefreshTokenTransport::forGuard($name, $app->make(ConfigRepository::class)),
        );

        self::wireGuardRebinds($app, $guard, $selection['tracks_global']);

        return $guard;
    }

    /**
     * Construct an `ApiKeyGuard`, failing here rather than on the first request
     * when the storage connection is malformed.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\Authentication\Guards\ApiKeyGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function createApiKeyGuard(Application $app, string $name, array $config): ApiKeyGuard
    {
        $providerName = $config['provider'] ?? '';

        /** @var \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider */
        $provider = IlluminateAuth::createUserProvider(is_string($providerName) ? $providerName : '');

        $selection = self::resolveGuardPrincipalResolver($app, $name, $config);

        StorageConnection::name();

        $guard = new ApiKeyGuard(
            $name,
            $provider,
            $selection['resolver'],
            $app->make(Dispatcher::class),
            $app->make('request'),
            $app->make(Timebox::class),
        );

        self::wireGuardRebinds($app, $guard, $selection['tracks_global']);

        return $guard;
    }

    /**
     * Resolve the guard's principal resolver and whether it tracks the global
     * binding.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return array{resolver: \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver, tracks_global: bool}
     *
     * @throws \InvalidArgumentException
     *
     * @internal
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
     * Make the `auth` binding the package's `AuthManager`, keeping one that
     * already is or extends it.
     *
     * @return void
     */
    protected function ownAuthManager(): void
    {
        $this->app->extend('auth', static function (IlluminateAuthManager $existing, Application $app): AuthManager {

            IlluminateAuth::clearResolvedInstance('auth');

            if ($existing instanceof AuthManager) {
                return $existing;
            }

            $manager = new AuthManager($app);
            $manager->inheritStateFrom($existing);

            return $manager;
        });
    }

    /**
     * Register the `model` user provider driver.
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
     * Register the `jwt` and `api_key` guard drivers.
     *
     * @return void
     */
    protected function registerGuardDrivers(): void
    {
        IlluminateAuth::extend(
            'jwt',
            static fn (Application $app, string $name, array $config): ContextualGuard => AuthenticationServiceProvider::createJwtGuard($app, $name, $config),
        );

        IlluminateAuth::extend(
            'api_key',
            static fn (Application $app, string $name, array $config): ContextualGuard => AuthenticationServiceProvider::createApiKeyGuard($app, $name, $config),
        );
    }

    /**
     * Register the package's event listeners.
     *
     * @return void
     */
    protected function registerListeners(): void
    {
        Event::listen(SessionAuthenticated::class, RecordSessionUsage::class);
        Event::listen(JobProcessing::class, ForgetGuardStateBeforeJob::class);
        Event::listen([Attempting::class, Validated::class, Login::class, Authenticated::class, Failed::class, OtherDeviceLogout::class], TrackCredentialAttempts::class);

        // Held work whose commit's callbacks stopped early runs once the
        // request, job or command ends, in the container it was held in
        $runDue = static function (): void {

            $container = Container::getInstance();

            if (!$container->resolved(RequiredWork::class)) {
                return;
            }

            $container->make(RequiredWork::class)->runDue();
        };

        $this->app->terminating($runDue);

        Event::listen([JobProcessed::class, JobExceptionOccurred::class, JobFailed::class, CommandFinished::class], $runDue);
    }

    /**
     * Register the package guards' `401` guest response with the exception
     * handler, after the application's own render callbacks.
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
     * Register the package's route middleware aliases and their place in the
     * kernel's middleware priority.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    private function registerMiddleware(Router $router): void
    {
        $router->aliasMiddleware('authentication.no-store', NoStore::class);
        $router->aliasMiddleware('authentication.refresh', UseRefreshCredential::class);
        $router->aliasMiddleware('authentication.pending', UsePendingCredential::class);

        $this->callAfterResolving(HttpKernel::class, static function (mixed $kernel): void {

            if (!$kernel instanceof Kernel) {
                return;
            }

            $kernel->prependToMiddlewarePriority(NoStore::class);
            $kernel->addToMiddlewarePriorityBefore(SubstituteBindings::class, UseRefreshCredential::class);
            $kernel->addToMiddlewarePriorityBefore(SubstituteBindings::class, UsePendingCredential::class);
        });
    }

    /**
     * Propagate rebinds of `request`, `events` and, optionally, the global
     * `PrincipalResolver` onto the guard.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  bool  $tracksGlobalPrincipalResolver
     * @return void
     */
    private static function wireGuardRebinds(Application $app, AbstractGuard $guard, bool $tracksGlobalPrincipalResolver): void
    {
        $app->refresh('request', $guard, 'setRequest');
        $app->refresh('events', $guard, 'setDispatcher');

        if (!$tracksGlobalPrincipalResolver) {
            return;
        }

        $app->refresh(PrincipalResolver::class, $guard, 'setPrincipalResolver');
    }
}
