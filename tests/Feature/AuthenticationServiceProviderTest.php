<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\Middleware\Authenticate as IlluminateAuthenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Application as ConsoleApplication;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
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
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use SineMacula\Laravel\Authentication\Http\Middleware\NoStore;
use SineMacula\Laravel\Authentication\Http\Middleware\UsePendingCredential;
use SineMacula\Laravel\Authentication\Http\Middleware\UseRefreshCredential;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
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
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\BuildsPlainValues;
use Tests\Fixtures\Context\ScriptedContributor;
use Tests\Fixtures\Database\ShippedMigrations;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubGuardScopedPrincipalResolver;
use Tests\Unit\Stubs\StubReplacementPrincipalResolver;

/**
 * Feature tests for the package AuthenticationServiceProvider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
final class AuthenticationServiceProviderTest extends TestCase
{
    use BuildsPlainValues;

    /** @var string Shared JWT secret for guard defaults. */
    private const string JWT_SECRET = 'service-provider-test-secret-32!!';

    /** @var string Signing algorithm for guard defaults. */
    private const string JWT_ALGORITHM = 'HS256';

    /** @var int Access-token TTL for guard defaults. */
    private const int JWT_TTL_MINUTES = 25;

    /**
     * The `auth` container binding resolves to the package `AuthManager`
     * subclass after the service provider boots.
     *
     * @return void
     */
    public function testAuthSingletonIsBoundToPackageAuthManager(): void
    {
        self::assertInstanceOf(AuthManager::class, app('auth'));
    }

    /**
     * The `model` user provider driver resolves the package `ModelProvider`.
     *
     * @return void
     */
    public function testModelProviderDriverIsRegistered(): void
    {
        $provider = IlluminateAuth::createUserProvider('identities');

        self::assertInstanceOf(ModelProvider::class, $provider);
    }

    /**
     * A `model` that is not a string is refused with the provider's message.
     *
     * @return void
     */
    public function testAModelThatIsNotAStringIsRefusedByTheProvider(): void
    {
        config()->set('auth.providers.numbered', ['driver' => 'model', 'model' => 123]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ModelProvider received unknown class "123" as its identity model.');

        IlluminateAuth::createUserProvider('numbered');
    }

    /**
     * The `jwt` guard driver resolves the package `JwtGuard`.
     *
     * @return void
     */
    public function testJwtGuardDriverCreatorIsRegistered(): void
    {
        self::assertInstanceOf(JwtGuard::class, app('auth')->guard('api'));
    }

    /**
     * The `api_key` guard driver resolves an `ApiKeyGuard` that follows later
     * rebinds and keeps a guard-local resolver override.
     *
     * @return void
     */
    public function testApiKeyGuardDriverCreatorIsRegistered(): void
    {
        $guard = app('auth')->guard('keys');

        self::assertInstanceOf(ApiKeyGuard::class, $guard);
        self::assertSame('keys', $guard->getName());
        self::assertInstanceOf(ModelProvider::class, $guard->getProvider());

        assert($this->app !== null);

        $replacement = new StubReplacementPrincipalResolver;
        $request     = Request::create('/rebound');
        $events      = new Dispatcher($this->app);

        $this->app->instance(PrincipalResolver::class, $replacement);
        $this->app->instance('request', $request);
        $this->app->instance('events', $events);

        self::assertSame($replacement, $guard->getPrincipalResolver());
        self::assertSame($request, $guard->getRequest());
        self::assertSame($events, $guard->getDispatcher());

        $override = app('auth')->guard('keys_override');

        self::assertInstanceOf(ApiKeyGuard::class, $override);
        self::assertInstanceOf(StubGuardScopedPrincipalResolver::class, $override->getPrincipalResolver());

        $this->app->instance(PrincipalResolver::class, new StubReplacementPrincipalResolver);

        self::assertInstanceOf(StubGuardScopedPrincipalResolver::class, $override->getPrincipalResolver());
    }

    /**
     * A `jwt` guard fails fast when the session model names a connection other
     * than the storage connection.
     *
     * @return void
     */
    public function testJwtGuardRejectsASessionModelOffTheStorageConnection(): void
    {
        config()->set('authentication.session.model', SeparateConnectionSession::class);

        $this->expectException(InvalidSessionModelConfigurationException::class);
        $this->expectExceptionMessage('must live on the storage connection');

        app('auth')->guard('api');
    }

    /**
     * An `api_key` guard is built whatever the session model is.
     *
     * @return void
     */
    public function testApiKeyGuardIgnoresTheSessionModel(): void
    {
        config()->set('authentication.session.model', '');

        self::assertInstanceOf(ApiKeyGuard::class, app('auth')->guard('keys'));
    }

    /**
     * An `api_key` guard fails fast when the storage connection is not a
     * connection name.
     *
     * @return void
     */
    public function testApiKeyGuardRejectsAMalformedStorageConnection(): void
    {
        config()->set('authentication.storage.connection', ['keys']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`authentication.storage.connection` must be a connection name, or null or empty for the default connection.');

        app('auth')->guard('keys');
    }

    /**
     * A guard configured with `driver = basic` fails to resolve.
     *
     * @return void
     */
    public function testBasicGuardDriverIsNotRegistered(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth driver [basic] for guard [cli] is not defined.');

        app('auth')->guard('cli');
    }

    /**
     * `RecordSessionUsage` listens for `SessionAuthenticated`.
     *
     * @return void
     */
    public function testSessionAuthenticatedListenerIsRegistered(): void
    {
        self::assertTrue(Event::hasListeners(SessionAuthenticated::class));

        $listeners = Event::getRawListeners()[SessionAuthenticated::class] ?? [];

        self::assertIsArray($listeners);
        self::assertContains(
            RecordSessionUsage::class,
            $listeners,
            'RecordSessionUsage must be registered as a listener for SessionAuthenticated.',
        );
    }

    /**
     * The package guards are reset before each queued job.
     *
     * @return void
     */
    public function testTheGuardsAreResetBeforeEachQueuedJob(): void
    {
        $listeners = Event::getRawListeners()[JobProcessing::class] ?? [];

        self::assertIsArray($listeners);
        self::assertContains(ForgetGuardStateBeforeJob::class, $listeners);
    }

    /**
     * Rows of `[an end of the request, job or command]`.
     *
     * @return iterable<string, array{0: \Closure(\Illuminate\Foundation\Application): mixed}>
     */
    public static function provideEndsOfTheUnitOfWork(): iterable
    {
        $job = static fn (Application $app): SyncJob => new SyncJob($app, '{}', 'sync', 'default');

        yield 'the application terminating' => [static fn (Application $app) => $app->terminate()];
        yield 'a job processed' => [static fn (Application $app) => Event::dispatch(new JobProcessed('sync', $job($app)))];
        yield 'a job that threw' => [static fn (Application $app) => Event::dispatch(new JobExceptionOccurred('sync', $job($app), new \RuntimeException('job')))];
        yield 'a job failed' => [static fn (Application $app) => Event::dispatch(new JobFailed('sync', $job($app), new \RuntimeException('job')))];
        yield 'a command finished' => [static fn (Application $app) => Event::dispatch(new CommandFinished('command', new ArrayInput([]), new NullOutput, 0))];
    }

    /**
     * The end of a request, job or command runs the held work that is due, and
     * only that.
     *
     * @param  \Closure(\Illuminate\Foundation\Application): mixed  $end
     * @return void
     */
    #[DataProvider('provideEndsOfTheUnitOfWork')]
    public function testTheEndOfTheUnitOfWorkRunsTheHeldWorkThatIsDue(\Closure $end): void
    {
        $app = $this->app;

        assert($app instanceof Application);

        /** @var \ArrayObject<int, string> $calls */
        $calls    = new \ArrayObject;
        $required = $app->make(RequiredWork::class);

        $required->hold(static fn (): bool => true, static function () use ($calls): void {
            $calls->append('due');
        });
        $required->hold(static fn (): bool => false, static function () use ($calls): void {
            $calls->append('waiting');
        });

        $end($app);
        $end($app);

        self::assertSame(['due'], $calls->getArrayCopy());
    }

    /**
     * The end of a request, job or command never creates the held work.
     *
     * @param  \Closure(\Illuminate\Foundation\Application): mixed  $end
     * @return void
     */
    #[DataProvider('provideEndsOfTheUnitOfWork')]
    public function testTheEndOfTheUnitOfWorkCreatesNoHeldWork(\Closure $end): void
    {
        $app = $this->app;

        assert($app instanceof Application);

        self::assertFalse($app->resolved(RequiredWork::class));

        $end($app);

        self::assertFalse($app->resolved(RequiredWork::class));
    }

    /**
     * Every guard's credential attempt is followed through Laravel's auth
     * events, so the rehash a guard runs during one is marked.
     *
     * @return void
     */
    public function testCredentialAttemptsAreTracked(): void
    {
        $listeners = Event::getRawListeners();

        foreach ([Attempting::class, Validated::class, Login::class, Authenticated::class, Failed::class, OtherDeviceLogout::class] as $event) {
            $registered = $listeners[$event] ?? [];

            self::assertIsArray($registered, $event);
            self::assertContains(TrackCredentialAttempts::class, $registered, $event);
        }
    }

    /**
     * The contextual accessors return `null` when the active guard is not
     * contextual.
     *
     * @return void
     */
    public function testContextualAccessorsReturnNullForNonContextualGuard(): void
    {
        config()->set('auth.defaults.guard', 'web');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        self::assertNull($manager->principal());
        self::assertNull($manager->session());
        self::assertNull($manager->tenant());
    }

    /**
     * The `PrincipalResolver` contract resolves to the package default
     * implementation when no custom resolver is bound.
     *
     * @return void
     */
    public function testPrincipalResolverIsBoundToDefaultImplementation(): void
    {
        self::assertInstanceOf(
            DefaultPrincipalResolver::class,
            app(PrincipalResolver::class),
        );
    }

    /**
     * The configuration check is registered as an Artisan command when the
     * application runs in the console.
     *
     * @return void
     */
    public function testTheConfigurationCheckIsRegisteredInTheConsole(): void
    {
        self::assertArrayHasKey('authentication:check', Artisan::all());
        self::assertInstanceOf(CheckConfigurationCommand::class, Artisan::all()['authentication:check']);
    }

    /**
     * Outside the console no command is registered.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testNoCommandIsRegisteredOutsideTheConsole(): void
    {
        $app = \Mockery::mock(Application::class)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturnFalse();

        $bootstrappers = new \ReflectionProperty(ConsoleApplication::class, 'bootstrappers');
        $before        = $bootstrappers->getValue();

        (new \ReflectionMethod(AuthenticationServiceProvider::class, 'registerCommands'))->invoke(new AuthenticationServiceProvider($app));

        self::assertSame($before, $bootstrappers->getValue());
    }

    /**
     * A guard takes the bound principal resolver, or its own override, fixed.
     *
     * @return void
     */
    public function testTheGuardsPrincipalResolverIsSelectedForTheConfigurationCheck(): void
    {
        $app = $this->app;

        assert($app instanceof Application);

        $global   = AuthenticationServiceProvider::resolveGuardPrincipalResolver($app, 'api', []);
        $override = AuthenticationServiceProvider::resolveGuardPrincipalResolver($app, 'api', ['principal_resolver' => StubReplacementPrincipalResolver::class]);

        self::assertSame(app(PrincipalResolver::class), $global['resolver']);
        self::assertTrue($global['tracks_global']);
        self::assertInstanceOf(StubReplacementPrincipalResolver::class, $override['resolver']);
        self::assertFalse($override['tracks_global']);
    }

    /**
     * Rows of `[an override, the problem it is reported as]`.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideUnusableResolverOverrides(): iterable
    {
        $notAnAbstract = 'Auth guard [api] principal_resolver must be a non-empty string container abstract.';

        yield 'an empty abstract' => ['', $notAnAbstract];
        yield 'an abstract that is not a string' => [[StubReplacementPrincipalResolver::class], $notAnAbstract];
        $notAResolver = 'Auth guard [api] principal_resolver [stdClass] resolved to [stdClass] instead of [' . PrincipalResolver::class . '].';

        yield 'an abstract that is not a resolver' => [\stdClass::class, $notAResolver];
        yield 'an abstract bound to a value' => ['config.resolver-value', 'Auth guard [api] principal_resolver [config.resolver-value] resolved to [string] instead of ['];
    }

    /**
     * An override that cannot be the guard's resolver is reported, naming the
     * guard and what it resolved to.
     *
     * @param  mixed  $override
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnusableResolverOverrides')]
    public function testAnUnusableResolverOverrideIsReported(mixed $override, string $message): void
    {
        $app = $this->app;

        assert($app instanceof Application);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $app->instance('config.resolver-value', 'not a resolver');

        AuthenticationServiceProvider::resolveGuardPrincipalResolver($app, 'api', ['principal_resolver' => $override]);
    }

    /**
     * The `ApplicationPolicy` contract resolves to the package policy, one
     * instance for the application.
     *
     * @return void
     */
    public function testApplicationPolicyIsBoundToThePackagePolicyAsASingleton(): void
    {
        self::assertInstanceOf(GuardApplicationPolicy::class, app(ApplicationPolicy::class));
        self::assertSame(app(ApplicationPolicy::class), app(ApplicationPolicy::class));
    }

    /**
     * The `AttemptLimiter` contract resolves to the database limiter, one
     * instance for the application.
     *
     * @return void
     */
    public function testAttemptLimiterIsBoundToTheDatabaseLimiterAsASingleton(): void
    {
        self::assertInstanceOf(DatabaseAttemptLimiter::class, app(AttemptLimiter::class));
        self::assertSame(app(AttemptLimiter::class), app(AttemptLimiter::class));
    }

    /**
     * The identifier normaliser registry is one instance for the application.
     *
     * @return void
     */
    public function testIdentifierNormalizersAreBoundAsASingleton(): void
    {
        self::assertSame(app(IdentifierNormalizers::class), app(IdentifierNormalizers::class));
    }

    /**
     * A JWT guard without an override, and its refresh exchange, track later
     * rebinds of the global `PrincipalResolver`.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testJwtGuardWithoutOverrideTracksLaterGlobalResolverRebind(): void
    {
        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $exchange = $this->exchangeOf($guard);

        self::assertInstanceOf(RefreshTokenExchange::class, $exchange);
        self::assertSame(
            $guard->getPrincipalResolver(),
            $this->contextOf($exchange)->resolver(),
        );

        $replacement = new StubReplacementPrincipalResolver;

        assert($this->app !== null);
        $this->app->instance(PrincipalResolver::class, $replacement);

        self::assertSame($replacement, $guard->getPrincipalResolver());
        self::assertSame($replacement, $this->contextOf($exchange)->resolver());
    }

    /**
     * A JWT guard keeps its override across later rebinds of the global
     * `PrincipalResolver`.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testJwtGuardWithOverrideIsNotClobberedByLaterGlobalResolverRebind(): void
    {
        $guard = app('auth')->guard('api_override');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $resolver = $guard->getPrincipalResolver();
        $exchange = $this->exchangeOf($guard);

        self::assertInstanceOf(StubGuardScopedPrincipalResolver::class, $resolver);
        self::assertInstanceOf(RefreshTokenExchange::class, $exchange);
        self::assertSame($resolver, $this->contextOf($exchange)->resolver());

        $replacement = new StubReplacementPrincipalResolver;

        assert($this->app !== null);
        $this->app->instance(PrincipalResolver::class, $replacement);

        self::assertSame($resolver, $guard->getPrincipalResolver());
        self::assertSame($resolver, $this->contextOf($exchange)->resolver());
        self::assertNotSame($replacement, $guard->getPrincipalResolver());
    }

    /**
     * The registry of configuration checks is a container singleton.
     *
     * @return void
     */
    public function testTheConfigurationChecksAreOneRegistry(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(ConfigurationChecks::class));
        self::assertSame(app(ConfigurationChecks::class), app(ConfigurationChecks::class));
    }

    /**
     * The sign-in method registry and factor policy are singletons, and the
     * per-request state is scoped.
     *
     * @return void
     */
    public function testRegistersTheSignInMethodsAndTheDefaultFactorPolicy(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(SignInMethodManager::class));
        self::assertSame(app(SignInMethodManager::class), app(SignInMethodManager::class));
        self::assertTrue($app->isShared(Rehashing::class));

        $rehashing = app(Rehashing::class);

        self::assertSame($rehashing, app(Rehashing::class));

        $app->forgetScopedInstances();

        self::assertNotSame($rehashing, app(Rehashing::class));
        self::assertTrue($app->isShared(KeptSessions::class));

        $kept = app(KeptSessions::class);

        self::assertSame($kept, app(KeptSessions::class));

        $app->forgetScopedInstances();

        self::assertNotSame($kept, app(KeptSessions::class));

        foreach ([WatchedSessions::class, RequiredWork::class] as $scoped) {

            self::assertTrue($app->isShared($scoped));

            $instance = app($scoped);

            self::assertSame($instance, app($scoped));

            $app->forgetScopedInstances();

            self::assertNotSame($instance, app($scoped));
        }

        self::assertTrue($app->isShared(AdditionalFactorPolicy::class));
        self::assertInstanceOf(NeverRequireAdditionalFactor::class, app(AdditionalFactorPolicy::class));
        self::assertTrue($app->isShared(PasskeyFactorGate::class));
        self::assertInstanceOf(NoPasskeyFactors::class, app(PasskeyFactorGate::class));
    }

    /**
     * The default tenant, requirement, external evidence and factor code
     * contracts are bound as singletons.
     *
     * @return void
     */
    public function testRegistersTheDefaultTenantPolicyAndRequirementCheck(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(TenantAuthenticationPolicy::class));
        self::assertInstanceOf(RequireNothingOfTenants::class, app(TenantAuthenticationPolicy::class));
        self::assertTrue($app->isShared(RequirementCheck::class));
        self::assertInstanceOf(MeetNoRequirement::class, app(RequirementCheck::class));
        self::assertTrue($app->isShared(ExternalEvidencePolicy::class));
        self::assertInstanceOf(InsufficientEvidence::class, app(ExternalEvidencePolicy::class));
        self::assertTrue($app->isShared(FactorCodeCounters::class));
        self::assertInstanceOf(RefuseFactorCodes::class, app(FactorCodeCounters::class));
    }

    /**
     * The default external identity links are bound as a singleton.
     *
     * @return void
     */
    public function testRegistersTheDefaultExternalIdentityLinks(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(ExternalIdentityLinks::class));
        self::assertInstanceOf(NoExternalLinks::class, app(ExternalIdentityLinks::class));
        self::assertSame(app(ExternalIdentityLinks::class), app(ExternalIdentityLinks::class));
    }

    /**
     * The default access contracts and tenant resolver are singletons.
     *
     * @return void
     */
    public function testRegistersTheDefaultAccessContracts(): void
    {
        $app = $this->app;

        assert($app !== null);

        $defaults = [
            ApplicationAccess::class => AdmitAnyPrincipal::class,
            TenantAccess::class      => OwnTenantOnly::class,
            TenantResolver::class    => ResolveNoTenant::class,
        ];

        foreach ($defaults as $contract => $default) {
            self::assertTrue($app->isShared($contract));
            self::assertInstanceOf($default, app($contract));
            self::assertSame(app($contract), app($contract));
        }
    }

    /**
     * The default scope registry is bound as a singleton.
     *
     * @return void
     */
    public function testRegistersTheDefaultScopeRegistry(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(ScopeRegistry::class));
        self::assertInstanceOf(AcceptAnyScope::class, app(ScopeRegistry::class));
        self::assertSame(app(ScopeRegistry::class), app(ScopeRegistry::class));
    }

    /**
     * The configured freshness policy is bound as a singleton.
     *
     * @return void
     */
    public function testRegistersTheConfiguredFreshnessPolicy(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(FreshnessPolicy::class));
        self::assertInstanceOf(ConfiguredFreshness::class, app(FreshnessPolicy::class));
        self::assertSame(app(FreshnessPolicy::class), app(FreshnessPolicy::class));
    }

    /**
     * The default breached-password checker is bound as a singleton.
     *
     * @return void
     */
    public function testRegistersTheDefaultBreachedPasswordChecker(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(BreachedPasswordChecker::class));
        self::assertInstanceOf(NoBreachedPasswordCheck::class, app(BreachedPasswordChecker::class));
        self::assertFalse(app(BreachedPasswordChecker::class)->isBreached('password'));
    }

    /**
     * Laravel's notification is the default password reset link sender, bound
     * as a singleton.
     *
     * @return void
     */
    public function testRegistersTheDefaultResetLinkSender(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(PasswordResetLinkSender::class));
        self::assertInstanceOf(NotifyingResetLinkSender::class, app(PasswordResetLinkSender::class));
    }

    /**
     * The default authentication contexts and the contributor registry are each
     * bound as a singleton.
     *
     * @return void
     */
    public function testRegistersTheDefaultContextsAndOneContributorRegistry(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue($app->isShared(AuthenticationContexts::class));
        self::assertInstanceOf(GuardAuthenticationContexts::class, app(AuthenticationContexts::class));
        self::assertSame(app(AuthenticationContexts::class), app(AuthenticationContexts::class));

        self::assertTrue($app->isShared(ContextContributors::class));

        app(ContextContributors::class)->register('sso', ScriptedContributor::class);

        self::assertSame(['sso' => ScriptedContributor::class], app(ContextContributors::class)->registered());
    }

    /**
     * Each contract an application may bind, with the package's default.
     *
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function providePackageDefaults(): iterable
    {
        yield 'principal resolver' => [PrincipalResolver::class, DefaultPrincipalResolver::class];
        yield 'application policy' => [ApplicationPolicy::class, GuardApplicationPolicy::class];
        yield 'application access' => [ApplicationAccess::class, AdmitAnyPrincipal::class];
        yield 'tenant access' => [TenantAccess::class, OwnTenantOnly::class];
        yield 'tenant resolver' => [TenantResolver::class, ResolveNoTenant::class];
        yield 'attempt limiter' => [AttemptLimiter::class, DatabaseAttemptLimiter::class];
        yield 'additional factor policy' => [AdditionalFactorPolicy::class, NeverRequireAdditionalFactor::class];
        yield 'passkey factor gate' => [PasskeyFactorGate::class, NoPasskeyFactors::class];
        yield 'tenant authentication policy' => [TenantAuthenticationPolicy::class, RequireNothingOfTenants::class];
        yield 'external identity links' => [ExternalIdentityLinks::class, NoExternalLinks::class];
        yield 'requirement check' => [RequirementCheck::class, MeetNoRequirement::class];
        yield 'external evidence policy' => [ExternalEvidencePolicy::class, InsufficientEvidence::class];
        yield 'factor code counters' => [FactorCodeCounters::class, RefuseFactorCodes::class];
        yield 'freshness policy' => [FreshnessPolicy::class, ConfiguredFreshness::class];
        yield 'scope registry' => [ScopeRegistry::class, AcceptAnyScope::class];
        yield 'breached password checker' => [BreachedPasswordChecker::class, NoBreachedPasswordCheck::class];
        yield 'password reset link sender' => [PasswordResetLinkSender::class, NotifyingResetLinkSender::class];
        yield 'authentication contexts' => [AuthenticationContexts::class, GuardAuthenticationContexts::class];
    }

    /**
     * Each default is the package's, resolved or not, and is a singleton.
     *
     * @param  class-string  $contract
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('providePackageDefaults')]
    public function testEachDefaultIsThePackagesDefault(string $contract, string $default): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertTrue(AuthenticationServiceProvider::isPackageDefault($app, $contract));
        self::assertTrue($app->isShared($contract));
        self::assertSame($default, get_class($app->make($contract)));
        self::assertSame($app->make($contract), $app->make($contract));
        self::assertTrue(AuthenticationServiceProvider::isPackageDefault($app, $contract));
    }

    /**
     * A binding made over a default is not the package's default.
     *
     * @return void
     */
    public function testARebindingIsNotThePackagesDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->singleton(PrincipalResolver::class, StubReplacementPrincipalResolver::class);

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, PrincipalResolver::class));

        $app->singleton(PrincipalResolver::class, static fn (): PrincipalResolver => new StubReplacementPrincipalResolver);

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, PrincipalResolver::class));
    }

    /**
     * A closure bound outside any class is not the package's default.
     *
     * @return void
     */
    public function testAnUnscopedClosureIsNotThePackagesDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->singleton(PrincipalResolver::class, \Closure::bind(static fn (): PrincipalResolver => new StubReplacementPrincipalResolver, null, null));

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, PrincipalResolver::class));
    }

    /**
     * An instance of another class is not the package's default.
     *
     * @return void
     */
    public function testAnInstanceOfAnotherClassIsNotThePackagesDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->instance(PrincipalResolver::class, new StubReplacementPrincipalResolver);

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, PrincipalResolver::class));
    }

    /**
     * A default extended before it resolves is not the package's default.
     *
     * @return void
     */
    public function testAnExtenderOnAnUnresolvedDefaultIsNotThePackagesDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->extend(ScopeRegistry::class, static fn (ScopeRegistry $registry): ScopeRegistry => $registry);

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, ScopeRegistry::class));
    }

    /**
     * A resolved default extended to another class is not the default.
     *
     * @return void
     */
    public function testAResolvedDefaultExtendedToAnotherClassIsNotThePackagesDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->make(PrincipalResolver::class);
        $app->extend(PrincipalResolver::class, static fn (): PrincipalResolver => new StubReplacementPrincipalResolver);

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, PrincipalResolver::class));
    }

    /**
     * A resolved default extended to its own class reads as the default.
     *
     * @return void
     */
    public function testAResolvedDefaultExtendedToItsOwnClassStillReadsAsThePackagesDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->make(PrincipalResolver::class);
        $app->extend(PrincipalResolver::class, static fn (PrincipalResolver $resolver): PrincipalResolver => $resolver);

        self::assertTrue(AuthenticationServiceProvider::isPackageDefault($app, PrincipalResolver::class));
    }

    /**
     * Parameters given to `makeWith()` reach the default's constructor.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testParametersGivenToMakeWithReachTheDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $config = new ConfigRepository;
        $policy = $app->makeWith(FreshnessPolicy::class, ['config' => $config]);

        self::assertSame(ConfiguredFreshness::class, $policy::class);
        self::assertSame($config, $this->readObjectProperty($policy, 'config'));
    }

    /**
     * A resolving callback runs once per construction of a default.
     *
     * @return void
     */
    public function testResolvingCallbacksRunOncePerConstructionOfADefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $runs = 0;

        $app->resolving(PrincipalResolver::class, static function () use (&$runs): void {
            $runs++;
        });

        $app->make(PrincipalResolver::class);
        $app->make(PrincipalResolver::class);

        $byPackage = $runs;

        $app->singleton(PrincipalResolver::class, DefaultPrincipalResolver::class);
        $app->make(PrincipalResolver::class);

        self::assertSame(1, $byPackage);
        self::assertSame(2, $runs);
    }

    /**
     * A default reached through an alias is not the package's default.
     *
     * @return void
     */
    public function testAnAliasedDefaultIsNotThePackagesDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->alias(StubReplacementPrincipalResolver::class, PrincipalResolver::class);

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, PrincipalResolver::class));
    }

    /**
     * An unbound contract or an internal binding is not a package default.
     *
     * @return void
     */
    public function testAnUnboundContractOrAnInternalBindingIsNotThePackagesDefault(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, JwtTokenServiceFactory::class));

        unset($app[PrincipalResolver::class]);

        self::assertFalse(AuthenticationServiceProvider::isPackageDefault($app, PrincipalResolver::class));
    }

    /**
     * Package guards follow later rebinds of the `events` dispatcher.
     *
     * @return void
     *
     * @throws \ReflectionException
     * @throws \Throwable
     */
    public function testJwtGuardTracksLaterEventDispatcherRebind(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 1);
        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        $this->migrateRateLimits();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        Event::fake([Attempting::class, Failed::class, AuthenticationFailed::class]);

        self::assertSame(Event::getFacadeRoot(), $guard->getDispatcher());
        self::assertFalse($guard->attempt(['password' => 'not-a-real-password']));

        Event::assertDispatched(Attempting::class, static fn (Attempting $event): bool => $event->guard === 'api');
        Event::assertDispatched(Failed::class, static fn (Failed $event): bool => $event->guard === 'api');
        Event::assertDispatched(
            AuthenticationFailed::class,
            static fn (AuthenticationFailed $event): bool => $event->context->guard === 'api' && $event->reason === FailureReason::INVALID_CREDENTIALS,
        );
    }

    /**
     * The refresh exchange follows the same `events` rebind as its guard.
     *
     * @return void
     *
     * @throws \ReflectionException
     * @throws \Random\RandomException
     */
    public function testJwtGuardRefreshExchangeTracksLaterEventDispatcherRebind(): void
    {
        $this->migrateRateLimits();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        Event::fake([Attempting::class, Failed::class, AuthenticationFailed::class]);

        self::assertSame(Event::getFacadeRoot(), $this->contextOf($this->exchangeOf($guard))->events());
        self::assertNull(Auth::sessions('api')->refresh(PresentedRefreshToken::fromBody('not-a-jwt'), self::requestClient())->session);

        Event::assertDispatched(
            AuthenticationFailed::class,
            static fn (AuthenticationFailed $event): bool => $event->context->guard === 'api' && $event->reason === FailureReason::TOKEN_INVALID,
        );
        Event::assertDispatched(Failed::class, static fn (Failed $event): bool => $event->guard === 'api');
    }

    /**
     * The refresh exchange resolves the transactions manager each time it
     * defers a revocation event.
     *
     * @return void
     */
    public function testJwtGuardRefreshExchangeResolvesTheCurrentTransactionsManager(): void
    {
        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $exchange = $this->exchangeOf($guard);

        self::assertInstanceOf(RefreshTokenExchange::class, $exchange);

        $transactions = $this->readObjectProperty($this->readObjectPropertyObject($exchange, 'afterCommit'), 'transactions');

        self::assertInstanceOf(\Closure::class, $transactions);
        self::assertSame(app('db.transactions'), $transactions());

        $replacement = new DatabaseTransactionsManager;

        app()->instance('db.transactions', $replacement);

        self::assertSame($replacement, $transactions());

        unset(app()['db.transactions']);

        self::assertNull($transactions());
    }

    /**
     * The guard-scoped JWT service factory is bound as a singleton.
     *
     * @return void
     */
    public function testJwtTokenServiceFactoryIsBound(): void
    {
        $factory = app(JwtTokenServiceFactory::class);

        self::assertInstanceOf(JwtTokenServiceFactory::class, $factory);
        self::assertSame($factory, app(JwtTokenServiceFactory::class));
    }

    /**
     * Booting over an already resolved Laravel manager replaces it with the
     * package's, which keeps its drivers.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBootingReplacesAResolvedLaravelManagerAndItsFacadeRoot(): void
    {
        $app = $this->app;

        assert($app !== null);

        $guard    = \Mockery::mock(Guard::class);
        $replaced = new IlluminateAuthManager($app);
        $replaced->extend('carried', fn (): Guard => $guard);

        $app->instance('auth', $replaced);
        IlluminateAuth::clearResolvedInstance('auth');

        self::assertSame($replaced, IlluminateAuth::getFacadeRoot());

        config()->set('auth.guards.carried', ['driver' => 'carried']);

        (new AuthenticationServiceProvider($app))->boot();

        $manager = $app->make('auth');

        self::assertInstanceOf(AuthManager::class, $manager);
        self::assertSame($manager, IlluminateAuth::getFacadeRoot());
        self::assertSame($guard, $manager->guard('carried'));
    }

    /**
     * `mergeConfigFrom` exposes the package config defaults at runtime.
     *
     * @return void
     */
    public function testPackageConfigIsMergedIntoConfigRepository(): void
    {
        self::assertSame('authentication_sessions', config('authentication.session.table'));
    }

    /**
     * The `authentication-config` publish group is registered with the
     * framework's publish registry.
     *
     * @return void
     */
    public function testConfigPublishingTagIsRegistered(): void
    {
        self::assertContains(
            'authentication-config',
            ServiceProvider::publishableGroups(),
        );
    }

    /**
     * The config tag publishes the package's config file.
     *
     * @return void
     */
    public function testConfigPublishingTagPublishesThePackageConfig(): void
    {
        $paths = [];

        foreach (ServiceProvider::pathsToPublish(AuthenticationServiceProvider::class, 'authentication-config') as $from => $to) {
            $paths[(string) realpath($from)] = $to;
        }

        self::assertSame([
            realpath(dirname(__DIR__, 2) . '/config/authentication.php') => config_path('authentication.php'),
        ], $paths);
    }

    /**
     * The `authentication-migrations` publish group is registered with the
     * framework's publish registry.
     *
     * @return void
     */
    public function testMigrationPublishingTagIsRegistered(): void
    {
        self::assertContains(
            'authentication-migrations',
            ServiceProvider::publishableGroups(),
        );
    }

    /**
     * The migrations tag publishes every shipped migration under its own file
     * name.
     *
     * @return void
     */
    public function testMigrationPublishingTagPublishesEveryShippedMigration(): void
    {
        $source = dirname(__DIR__, 2) . '/database/migrations/';
        $paths  = [];

        foreach (ServiceProvider::pathsToPublish(AuthenticationServiceProvider::class, 'authentication-migrations') as $from => $to) {
            $paths[(string) realpath($from)] = $to;
        }

        $expected   = [];
        $migrations = [
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

        foreach ($migrations as $migration) {
            $expected[(string) realpath($source . $migration)] = database_path('migrations/' . $migration);
        }

        self::assertSame($expected, $paths);
    }

    /**
     * The WebAuthn wrapper is shared by every guard's passkeys.
     *
     * @return void
     */
    public function testTheWebAuthnWrapperIsShared(): void
    {
        self::assertSame(app(WebAuthn::class), app(WebAuthn::class));
    }

    /**
     * Laravel's `auth` middleware resolves to the package-aware subclass.
     *
     * @return void
     */
    public function testAuthMiddlewareResolvesToThePackageAwareSubclass(): void
    {
        self::assertInstanceOf(Authenticate::class, app(IlluminateAuthenticate::class));
    }

    /**
     * The credential middleware are aliased and ordered before
     * `SubstituteBindings`, with `authentication.no-store` first.
     *
     * @return void
     */
    public function testTheRouteMiddlewareAreAliasedAndOrderedInThePriority(): void
    {
        $router = app(Router::class);
        $kernel = app(HttpKernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);
        self::assertSame(NoStore::class, $router->getMiddleware()['authentication.no-store'] ?? null);
        self::assertSame(UseRefreshCredential::class, $router->getMiddleware()['authentication.refresh'] ?? null);
        self::assertSame(UsePendingCredential::class, $router->getMiddleware()['authentication.pending'] ?? null);

        foreach ([$kernel->getMiddlewarePriority(), $router->middlewarePriority] as $priority) {

            self::assertSame(NoStore::class, $priority[0] ?? null);

            $bindings = array_search(SubstituteBindings::class, $priority, true);
            $refresh  = array_search(UseRefreshCredential::class, $priority, true);
            $pending  = array_search(UsePendingCredential::class, $priority, true);

            self::assertIsInt($bindings);
            self::assertIsInt($refresh);
            self::assertIsInt($pending);
            self::assertLessThan($bindings, $refresh);
            self::assertLessThan($bindings, $pending);
        }
    }

    /**
     * The exception handler renders a guest on a package guard as a JSON `401`,
     * even for an HTML request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExceptionHandlerRendersPackageGuardGuestsAsUnauthorized(): void
    {
        $handler = app(ExceptionHandler::class);

        $response = $handler->render(
            Request::create('/guarded', 'GET', server: ['HTTP_ACCEPT' => 'text/html']),
            new AuthenticationException('Unauthenticated.', ['api']),
        );

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('{"message":"Unauthenticated."}', $response->getContent());
    }

    /**
     * A custom exception handler, not Laravel's foundation one, is left alone.
     *
     * @return void
     *
     * @throws \Illuminate\Container\EntryNotFoundException
     * @throws \Illuminate\Contracts\Container\CircularDependencyException
     */
    public function testCustomExceptionHandlerIsLeftAlone(): void
    {
        $custom = new class implements ExceptionHandler {
            /**
             * Report nothing.
             *
             * @param  \Throwable  $e
             * @return void
             */
            #[\Override]
            public function report(\Throwable $e): void {}

            /**
             * Report nothing.
             *
             * @param  \Throwable  $e
             * @return bool
             */
            #[\Override]
            public function shouldReport(\Throwable $e): bool
            {
                return false;
            }

            /**
             * Render a bare response.
             *
             * @param  mixed  $request
             * @param  \Throwable  $e
             * @return \Symfony\Component\HttpFoundation\Response
             */
            #[\Override]
            public function render(mixed $request, \Throwable $e): Response
            {
                return new Response('', 500);
            }

            /**
             * Render nothing to the console.
             *
             * @param  mixed  $output
             * @param  \Throwable  $e
             * @return void
             */
            #[\Override]
            public function renderForConsole(mixed $output, \Throwable $e): void {}
        };

        app()->singleton(ExceptionHandler::class, static fn (): ExceptionHandler => $custom);

        self::assertSame($custom, app()->get(ExceptionHandler::class));
    }

    /**
     * The package `AuthManager` is a subclass of Laravel's framework
     * `AuthManager`.
     *
     * @return void
     */
    public function testResolvedAuthManagerExtendsFrameworkManager(): void
    {
        self::assertInstanceOf(IlluminateAuthManager::class, app('auth'));
    }

    /**
     * Register the package service provider against the Testbench application.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthenticationServiceProvider::class];
    }

    /**
     * Configure the package, a `model` provider, a `jwt` guard and a `basic`
     * guard no driver serves.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('app.key', 'base64:' . base64_encode('service-provider-test-app-key-32'));
        $config->set('authentication.jwt.keys', ['default' => self::JWT_SECRET]);
        $config->set('authentication.jwt.active_kid', 'default');
        $config->set('authentication.jwt.algorithm', self::JWT_ALGORITHM);
        $config->set('authentication.jwt.issuer', 'https://issuer.example.test');
        $config->set('authentication.jwt.audience', 'https://api.example.test');
        $config->set('authentication.jwt.access_ttl_minutes', self::JWT_TTL_MINUTES);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubAuthenticatableModel::class,
        ]);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.guards.keys', [
            'driver'   => 'api_key',
            'provider' => 'identities',
        ]);

        $config->set('auth.guards.keys_override', [
            'driver'             => 'api_key',
            'provider'           => 'identities',
            'principal_resolver' => StubGuardScopedPrincipalResolver::class,
        ]);

        $config->set('auth.guards.api_override', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => StubGuardScopedPrincipalResolver::class,
        ]);

        $config->set('auth.guards.cli', [
            'driver'   => 'basic',
            'provider' => 'identities',
        ]);
    }

    /**
     * Create the shipped rate limits table and drop it when the application
     * goes.
     *
     * @return void
     */
    private function migrateRateLimits(): void
    {
        ShippedMigrations::up('2026_04_06_000002_create_rate_limits_table.php');

        $this->beforeApplicationDestroyed(static function (): void {
            ShippedMigrations::down('2026_04_06_000002_create_rate_limits_table.php');
        });
    }

    /**
     * The refresh exchange of the guard's session service.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return mixed
     *
     * @throws \ReflectionException
     */
    private function exchangeOf(JwtGuard $guard): mixed
    {
        return $this->readObjectProperty($this->readObjectPropertyObject(Auth::sessions($guard->getName()), 'refreshes'), 'exchange');
    }

    /**
     * The guard context a refresh exchange is bound to.
     *
     * @param  mixed  $exchange
     * @return \SineMacula\Laravel\Authentication\Runtime\GuardContext
     *
     * @throws \ReflectionException
     */
    private function contextOf(mixed $exchange): GuardContext
    {
        assert($exchange instanceof RefreshTokenExchange);

        $context = $this->readObjectProperty($exchange, 'context');

        assert($context instanceof GuardContext);

        return $context;
    }

    /**
     * Read a private or protected property off an object via reflection.
     *
     * @param  object  $target
     * @param  string  $property
     * @return mixed
     *
     * @throws \ReflectionException
     *
     * @SuppressWarnings("php:S3011")
     */
    private function readObjectProperty(object $target, string $property): mixed
    {
        $reflectionProperty = (new \ReflectionClass($target))->getProperty($property);

        return $reflectionProperty->getValue($target);
    }

    /**
     * Read a property holding an object, failing the test when it holds none.
     *
     * @param  object  $target
     * @param  string  $property
     * @return object
     *
     * @throws \ReflectionException
     */
    private function readObjectPropertyObject(object $target, string $property): object
    {
        $value = $this->readObjectProperty($target, $property);

        self::assertIsObject($value, "The {$property} property holds no object.");

        return $value;
    }
}
