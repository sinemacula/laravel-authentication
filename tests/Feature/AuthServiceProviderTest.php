<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Feature tests for the package AuthServiceProvider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthServiceProvider::class)]
final class AuthServiceProviderTest extends TestCase
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
     * The `basic` guard driver creator is registered against Laravel's `Auth`
     * factory so resolving an `auth.guards.*.driver = basic` guard yields the
     * package `BasicGuard`.
     *
     * @return void
     */
    public function testBasicGuardDriverCreatorIsRegistered(): void
    {
        self::assertInstanceOf(BasicGuard::class, app('auth')->guard('cli'));
    }

    /**
     * The `DeviceAuthenticated` event listener is registered with the
     * dispatcher and resolves to the package `UpdateDeviceTimestamp` invokable
     * listener class.
     *
     * @return void
     */
    public function testDeviceAuthenticatedListenerIsRegistered(): void
    {
        self::assertTrue(Event::hasListeners(DeviceAuthenticated::class));

        $listeners = Event::getRawListeners()[DeviceAuthenticated::class] ?? [];

        self::assertContains(
            UpdateDeviceTimestamp::class,
            $listeners,
            'UpdateDeviceTimestamp must be registered as a listener for DeviceAuthenticated.',
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

        $replacement = new AuthServiceProviderTestReplacementResolver;

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

        self::assertInstanceOf(AuthServiceProviderTestGuardScopedResolver::class, $resolver);
        self::assertInstanceOf(RefreshTokenExchange::class, $exchange);
        self::assertSame($resolver, $this->readObjectProperty($exchange, 'resolver'));

        $replacement = new AuthServiceProviderTestReplacementResolver;

        $this->app->instance(PrincipalResolver::class, $replacement);

        self::assertSame($resolver, $this->readObjectProperty($guard, 'resolver'));
        self::assertSame($resolver, $this->readObjectProperty($exchange, 'resolver'));
        self::assertNotSame($replacement, $this->readObjectProperty($guard, 'resolver'));
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
        return [AuthServiceProvider::class];
    }

    /**
     * Define the Testbench environment with package config and an
     * `auth.guards`/`auth.providers` setup that exercises both the `model`
     * user provider driver and the `jwt`/`basic` guard driver creators.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('authentication.jwt.secret', self::JWT_SECRET);
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
            'principal_resolver' => AuthServiceProviderTestGuardScopedResolver::class,
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

/**
 * Stub guard-scoped resolver for rebind tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthServiceProviderTestGuardScopedResolver implements PrincipalResolver
{
    /**
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        unset($identity, $hint);

        return null;
    }
}

/**
 * Stub replacement resolver for global rebind tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthServiceProviderTestReplacementResolver implements PrincipalResolver
{
    /**
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        unset($identity, $hint);

        return null;
    }
}
