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
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Foundation\Http\Kernel;
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
use SineMacula\Laravel\Authentication\Console\PruneSessionsCommand;
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
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;

/**
 * Package service provider: registers the package's configuration, auth
 * manager, guard (`jwt`, `api_key`) and provider drivers, sign-in collaborators
 * and policies, middleware, listener, publishing tags and console command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthenticationServiceProvider extends ServiceProvider
{
    /** @var list<string> File names of the shipped migrations, published under the `authentication-migrations` tag. */
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
     * Register container bindings.
     *
     * Every binding is a default: one that the application or another package
     * made before this provider registers is kept, so a sibling's policy is
     * never replaced by the package's (an additional-factor policy by
     * `NeverRequireAdditionalFactor`, a scope registry by `AcceptAnyScope`),
     * and one made after replaces the default, as any later binding does.
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

        $this->app->singletonIf(PrincipalResolver::class, DefaultPrincipalResolver::class);
        $this->app->singletonIf(ApplicationPolicy::class, GuardApplicationPolicy::class);
        $this->app->singletonIf(ApplicationAccess::class, AdmitAnyPrincipal::class);
        $this->app->singletonIf(TenantAccess::class, OwnTenantOnly::class);
        $this->app->singletonIf(TenantResolver::class, ResolveNoTenant::class);
        $this->app->singletonIf(IdentifierNormalizers::class);
        $this->app->singletonIf(AttemptLimiter::class, DatabaseAttemptLimiter::class);
        $this->app->singletonIf(SignInMethodManager::class);
        $this->app->scopedIf(Rehashing::class);
        $this->app->singletonIf(AdditionalFactorPolicy::class, NeverRequireAdditionalFactor::class);
        $this->app->singletonIf(PasskeyFactorGate::class, NoPasskeyFactors::class);
        $this->app->singletonIf(TenantAuthenticationPolicy::class, RequireNothingOfTenants::class);
        $this->app->singletonIf(ExternalIdentityLinks::class, NoExternalLinks::class);
        $this->app->singletonIf(RequirementCheck::class, MeetNoRequirement::class);
        $this->app->singletonIf(ExternalEvidencePolicy::class, InsufficientEvidence::class);
        $this->app->singletonIf(FactorCodeCounters::class, RefuseFactorCodes::class);
        $this->app->singletonIf(FreshnessPolicy::class, ConfiguredFreshness::class);
        $this->app->singletonIf(WebAuthn::class);
        $this->app->singletonIf(ScopeRegistry::class, AcceptAnyScope::class);
        $this->app->singletonIf(BreachedPasswordChecker::class, NoBreachedPasswordCheck::class);
        $this->app->singletonIf(PasswordResetLinkSender::class, NotifyingResetLinkSender::class);
        $this->app->singletonIf(AuthenticationContexts::class, GuardAuthenticationContexts::class);
        $this->app->singletonIf(ContextContributors::class);
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
     * Construct a `JwtGuard` from the supplied container, guard name, and
     * Laravel guard config block. A session model that is misconfigured, or not
     * on the storage connection, fails here rather than on the first request.
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
     * Construct an `ApiKeyGuard` from the supplied container, guard name, and
     * Laravel guard config block. A malformed storage connection, where the
     * guard's keys live, fails here rather than on the first request; the
     * session model is not read, since keys have no sessions.
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
     * Resolve the effective principal resolver for the guard; the guard driver
     * and `authentication:check` both use it, which is the only reason it is
     * public: it is not part of the package's API.
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
     * Make the `auth` binding the package's `AuthManager`: the package owns it,
     * and its guards, its accessors and the facade rely on it.
     *
     * A manager that is already the package's, or a subclass of it (how an
     * application customises the manager, bound in a `register()`), is kept.
     * Any other is replaced by the package's, which takes over its guard and
     * provider creators, its user resolver and its resolved guards
     * (`AuthManager::inheritStateFrom()`); a subclass's own behaviour is lost.
     * Applied when `auth` resolves, or at once when it already has; a binding
     * of `auth` made after the package boots is not supported. The facades'
     * cached manager is forgotten, so a facade used before the swap reaches the
     * package's.
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
     * Register the `jwt` and `api_key` guard driver creators against Laravel's
     * `Auth` factory.
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
     * Register the `SessionAuthenticated` listener, the reset of the package
     * guards before each queued job, and the tracking of credential attempts
     * that marks an automatic rehash.
     *
     * @return void
     */
    protected function registerListeners(): void
    {
        Event::listen(SessionAuthenticated::class, RecordSessionUsage::class);
        Event::listen(JobProcessing::class, ForgetGuardStateBeforeJob::class);
        Event::listen([Attempting::class, Validated::class, Login::class, Authenticated::class, Failed::class, OtherDeviceLogout::class], TrackCredentialAttempts::class);
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

        $this->commands([CheckConfigurationCommand::class, PruneSessionsCommand::class]);
    }

    /**
     * Register the package's route middleware aliases, each opt-in per route,
     * and order them in the HTTP kernel's middleware priority:
     * `authentication.no-store` first, so on a route that lists it, it wraps
     * every other route middleware the kernel sorts; `authentication.refresh`
     * and `authentication.pending`, with which a route declares the credential
     * it authenticates with, before `SubstituteBindings`, so the declaration is
     * in place before any parameter is bound. The priority is changed once the
     * kernel is resolved, after the application's own `withMiddleware()`
     * settings.
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
     * Register container `refresh` hooks that propagate runtime rebinds of
     * `request`, `events`, and optionally the global `PrincipalResolver` onto
     * the supplied guard.
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
