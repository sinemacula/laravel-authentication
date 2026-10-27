<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Middleware\Authenticate as IlluminateAuthenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Symfony\Component\HttpFoundation\Response;
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
     * The `model` user provider driver is registered against Laravel's `Auth`
     * factory and resolves the package `ModelProvider` for a config that uses
     * `driver = model`.
     *
     * @return void
     */
    public function testModelProviderDriverIsRegistered(): void
    {
        $provider = IlluminateAuth::createUserProvider('identities');

        self::assertInstanceOf(ModelProvider::class, $provider);
    }

    /**
     * The `jwt` guard driver creator is registered against Laravel's `Auth`
     * factory so resolving an `auth.guards.*.driver = jwt` guard yields the
     * package `JwtGuard`.
     *
     * @return void
     */
    public function testJwtGuardDriverCreatorIsRegistered(): void
    {
        self::assertInstanceOf(JwtGuard::class, app('auth')->guard('api'));
    }

    /**
     * The package registers no `basic` guard driver, so a guard configured with
     * `driver = basic` fails to resolve.
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
     * The `DeviceAuthenticated` event listener is registered with the
     * dispatcher and resolves to the package `RecordDeviceUsage` invokable
     * listener class.
     *
     * @return void
     */
    public function testDeviceAuthenticatedListenerIsRegistered(): void
    {
        self::assertTrue(Event::hasListeners(DeviceAuthenticated::class));

        $listeners = Event::getRawListeners()[DeviceAuthenticated::class] ?? [];

        self::assertContains(
            RecordDeviceUsage::class,
            $listeners,
            'RecordDeviceUsage must be registered as a listener for DeviceAuthenticated.',
        );
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
        self::assertNull($manager->device());
        self::assertNull($manager->tenant());
        self::assertNull($manager->type());
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
     * JWT guards without a guard-local override should continue tracking later
     * rebinds of the app-wide `PrincipalResolver::class` binding, and the
     * refresh exchange must stay aligned with the guard's resolver.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testJwtGuardWithoutOverrideTracksLaterGlobalResolverRebind(): void
    {
        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $exchange = $this->readObjectProperty($guard, 'exchange');

        self::assertInstanceOf(RefreshTokenExchange::class, $exchange);
        self::assertSame(
            $this->readObjectProperty($guard, 'resolver'),
            $this->readObjectProperty($exchange, 'resolver'),
        );

        $replacement = new StubReplacementPrincipalResolver;

        assert($this->app !== null);
        $this->app->instance(PrincipalResolver::class, $replacement);

        self::assertSame($replacement, $this->readObjectProperty($guard, 'resolver'));
        self::assertSame($replacement, $this->readObjectProperty($exchange, 'resolver'));
    }

    /**
     * JWT guards with a guard-local override must not be clobbered by later
     * rebinds of the app-wide `PrincipalResolver::class` binding.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testJwtGuardWithOverrideIsNotClobberedByLaterGlobalResolverRebind(): void
    {
        $guard = app('auth')->guard('api_override');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $resolver = $this->readObjectProperty($guard, 'resolver');
        $exchange = $this->readObjectProperty($guard, 'exchange');

        self::assertInstanceOf(StubGuardScopedPrincipalResolver::class, $resolver);
        self::assertInstanceOf(RefreshTokenExchange::class, $exchange);
        self::assertSame($resolver, $this->readObjectProperty($exchange, 'resolver'));

        $replacement = new StubReplacementPrincipalResolver;

        assert($this->app !== null);
        $this->app->instance(PrincipalResolver::class, $replacement);

        self::assertSame($resolver, $this->readObjectProperty($guard, 'resolver'));
        self::assertSame($resolver, $this->readObjectProperty($exchange, 'resolver'));
        self::assertNotSame($replacement, $this->readObjectProperty($guard, 'resolver'));
    }

    /**
     * Package guards follow later rebinds of the `events` dispatcher, so an
     * `Event::fake()` (or any dispatcher swap) made after a guard resolves
     * still receives that guard's events.
     *
     * @return void
     *
     * @throws \ReflectionException
     * @throws \Throwable
     */
    public function testJwtGuardTracksLaterEventDispatcherRebind(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 1);

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        Event::fake([Attempting::class, Failed::class]);

        self::assertSame(Event::getFacadeRoot(), $this->readObjectProperty($guard, 'events'));
        self::assertFalse($guard->attempt(['password' => 'not-a-real-password']));

        Event::assertDispatched(Attempting::class, static fn (Attempting $event): bool => $event->guard === 'api');
        Event::assertDispatched(Failed::class, static fn (Failed $event): bool => $event->guard === 'api');
    }

    /**
     * The refresh exchange follows the same `events` rebind as its guard: after
     * an `Event::fake()` made once the guard has resolved, a failed refresh
     * dispatches `RefreshFailed` to the fake, alongside the guard's own
     * `Attempting` and `Failed`.
     *
     * @return void
     *
     * @throws \ReflectionException
     * @throws \Random\RandomException
     */
    public function testJwtGuardRefreshExchangeTracksLaterEventDispatcherRebind(): void
    {
        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        Event::fake([Attempting::class, Failed::class, RefreshFailed::class]);

        self::assertSame(Event::getFacadeRoot(), $this->readObjectProperty($this->readObjectProperty($guard, 'exchange'), 'events'));
        self::assertNull($guard->refresh('not-a-jwt'));

        Event::assertDispatched(
            RefreshFailed::class,
            static fn (RefreshFailed $event): bool => $event->guard === 'api' && $event->reason === RefreshFailureReason::TOKEN_INVALID,
        );
        Event::assertDispatched(Failed::class, static fn (Failed $event): bool => $event->guard === 'api');
    }

    /**
     * The guard-scoped JWT service factory is bound into the container so
     * guards and the public `Auth::jwt()` surface resolve through the same
     * internal construction path.
     *
     * @return void
     */
    public function testJwtTokenServiceFactoryIsBound(): void
    {
        self::assertInstanceOf(JwtTokenServiceFactory::class, app(JwtTokenServiceFactory::class));
    }

    /**
     * `mergeConfigFrom` exposes the package config defaults at runtime - the
     * `device.table` default of `'devices'` is the canonical assertion.
     *
     * @return void
     */
    public function testPackageConfigIsMergedIntoConfigRepository(): void
    {
        self::assertSame('devices', config('authentication.device.table'));
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
     * Laravel's `auth` middleware resolves to the package-aware subclass.
     *
     * @return void
     */
    public function testAuthMiddlewareResolvesToThePackageAwareSubclass(): void
    {
        self::assertInstanceOf(Authenticate::class, app(IlluminateAuthenticate::class));
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
     * `AuthManager`. This is a sanity guard alongside the `AuthManagerTest`
     * assertion to ensure the service-provider override does not regress to a
     * sibling class.
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
     * Define the Testbench environment with package config and an
     * `auth.guards`/`auth.providers` setup that exercises both the `model` user
     * provider driver and the `jwt` guard driver creator, plus a `basic` guard
     * that no registered driver serves.
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

        $config->set('authentication.jwt.keys', ['default' => self::JWT_SECRET]);
        $config->set('authentication.jwt.active_kid', 'default');
        $config->set('authentication.jwt.algorithm', self::JWT_ALGORITHM);
        $config->set('authentication.jwt.access_ttl_minutes', self::JWT_TTL_MINUTES);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubAuthenticatableModel::class,
        ]);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
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
}
