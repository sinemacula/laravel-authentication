<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Unit tests for the package AuthServiceProvider.
 *
 * Boots Orchestra Testbench with the package service provider so the
 * full register/boot lifecycle runs against a real Laravel container.
 * Each test asserts a single registration concern: container bindings,
 * driver creators, facade macros, listeners, publishing tags, and
 * config merging.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(AuthServiceProvider::class)]
final class AuthServiceProviderTest extends TestCase
{
    /** @var string The shared JWT secret used by the bound JwtTokenService. */
    private const string JWT_SECRET = 'service-provider-test-secret-32!!';

    /** @var string The signing algorithm used by the bound JwtTokenService. */
    private const string JWT_ALGORITHM = 'HS256';

    /** @var int The access-token TTL used by the bound JwtTokenService. */
    private const int JWT_TTL_MINUTES = 25;

    /** @var string Kid used by the current-generation key in the kid-mode config tests. */
    private const string KID_NEW = '2026-04';

    /** @var string Kid used by the previous-generation key in the kid-mode config tests. */
    private const string KID_OLD = '2026-03';

    /**
     * The `auth` container binding resolves to the package
     * `AuthManager` subclass after the service provider boots.
     *
     * @return void
     */
    public function testAuthSingletonIsBoundToPackageAuthManager(): void
    {
        self::assertInstanceOf(AuthManager::class, app('auth'));
    }

    /**
     * The `model` user provider driver is registered against
     * Laravel's `Auth` factory and resolves the package
     * `ModelProvider` for a config that uses `driver = model`.
     *
     * @return void
     */
    public function testModelProviderDriverIsRegistered(): void
    {
        $provider = IlluminateAuth::createUserProvider('identities');

        self::assertInstanceOf(ModelProvider::class, $provider);
    }

    /**
     * The `jwt` guard driver creator is registered against Laravel's
     * `Auth` factory so resolving an `auth.guards.*.driver = jwt`
     * guard yields the package `JwtGuard`.
     *
     * @return void
     */
    public function testJwtGuardDriverCreatorIsRegistered(): void
    {
        self::assertInstanceOf(JwtGuard::class, app('auth')->guard('api'));
    }

    /**
     * The `basic` guard driver creator is registered against
     * Laravel's `Auth` factory so resolving an
     * `auth.guards.*.driver = basic` guard yields the package
     * `BasicGuard`.
     *
     * @return void
     */
    public function testBasicGuardDriverCreatorIsRegistered(): void
    {
        self::assertInstanceOf(BasicGuard::class, app('auth')->guard('cli'));
    }

    /**
     * The `DeviceAuthenticated` event listener is registered with
     * the dispatcher and resolves to the package
     * `UpdateDeviceTimestamp` invokable listener class.
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
     * The package `AuthManager` exposes the six contextual accessors
     * (`principal`, `device`, `organization`, `scope`, `isInternal`,
     * `isExternal`) directly as instance methods so the framework
     * `Auth::principal()` etc. calls work without macro registration.
     *
     * @return void
     */
    public function testAuthManagerExposesContextualAccessorMethods(): void
    {
        $reflection = new \ReflectionClass(AuthManager::class);

        self::assertTrue($reflection->hasMethod('principal'));
        self::assertTrue($reflection->hasMethod('device'));
        self::assertTrue($reflection->hasMethod('organization'));
        self::assertTrue($reflection->hasMethod('scope'));
        self::assertTrue($reflection->hasMethod('isInternal'));
        self::assertTrue($reflection->hasMethod('isExternal'));
    }

    /**
     * The contextual accessors return the safe fallback values
     * (`null` / `false`) when the active guard is not contextual.
     *
     * @return void
     */
    public function testContextualAccessorsReturnSafeFallbacksForNonContextualGuard(): void
    {
        config()->set('auth.defaults.guard', 'web');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        self::assertNull($manager->principal());
        self::assertNull($manager->device());
        self::assertNull($manager->organization());
        self::assertNull($manager->scope());
        self::assertFalse($manager->isInternal());
        self::assertFalse($manager->isExternal());
    }

    /**
     * The `PrincipalResolver` contract resolves to the package
     * default implementation when no custom resolver is bound.
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
     * The `JwtTokenService` is bound from package config — the
     * resolved instance reflects the configured secret (via the
     * keyring's active key), algorithm, and TTL via reflection on
     * its private/promoted properties.
     *
     * @return void
     */
    public function testJwtTokenServiceIsBoundFromConfig(): void
    {
        $service = app(JwtTokenService::class);

        self::assertInstanceOf(JwtTokenService::class, $service);

        $reflection = new \ReflectionClass($service);

        $keyringProp = $reflection->getProperty('keyring');
        $algorithm   = $reflection->getProperty('algorithm');
        $ttl         = $reflection->getProperty('accessTtlMinutes');

        $keyring = $keyringProp->getValue($service);    // NOSONAR

        self::assertInstanceOf(\SineMacula\Laravel\Authentication\Jwt\JwtKeyring::class, $keyring);
        self::assertSame(self::JWT_SECRET, $keyring->activeKey()->getKeyMaterial());    // NOSONAR
        self::assertSame(self::JWT_ALGORITHM, $algorithm->getValue($service));  // NOSONAR
        self::assertSame(self::JWT_TTL_MINUTES, $ttl->getValue($service));  // NOSONAR
    }

    /**
     * `mergeConfigFrom` exposes the package config defaults at
     * runtime — the `device.table` default of `'devices'` is the
     * canonical assertion.
     *
     * @return void
     */
    public function testPackageConfigIsMergedIntoConfigRepository(): void
    {
        self::assertSame('devices', config('laravel-authentication.device.table'));
    }

    /**
     * `buildKeyring` selects kid mode when `jwt.keys` is populated:
     * the resulting keyring exposes the configured `active_kid`
     * (rather than `null`, which is the legacy single-secret signal),
     * and `verificationKeys()` returns a `kid → Key` map covering
     * every entry in the supplied keys array.
     *
     * @return void
     */
    public function testBuildKeyringPicksKidModeWhenKeysAreConfigured(): void
    {
        $newSecret = 'kid-mode-new-secret-with-32-bytes!';
        $oldSecret = 'kid-mode-old-secret-with-32-bytes!';

        $config = new ConfigRepository([
            'laravel-authentication' => [
                'jwt' => [
                    'algorithm' => 'HS256',
                    'secret'    => null,
                    'keys'      => [
                        self::KID_NEW => $newSecret,
                        self::KID_OLD => $oldSecret,
                    ],
                    'active_kid' => self::KID_NEW,
                ],
            ],
        ]);

        $reflection = new \ReflectionClass(AuthServiceProvider::class);

        $build = $reflection->getMethod('buildKeyring');

        /** @var \SineMacula\Laravel\Authentication\Jwt\JwtKeyring $keyring */
        $keyring = $build->invoke(null, $config, 'HS256');

        self::assertInstanceOf(\SineMacula\Laravel\Authentication\Jwt\JwtKeyring::class, $keyring);
        self::assertSame(self::KID_NEW, $keyring->activeKid());

        $verificationKeys = $keyring->verificationKeys();

        self::assertIsArray($verificationKeys);
        self::assertArrayHasKey(self::KID_NEW, $verificationKeys);
        self::assertArrayHasKey(self::KID_OLD, $verificationKeys);
    }

    /**
     * `buildKeyring` rejects an integer-indexed `jwt.keys` config (a
     * common operator mistake when writing `['secret_a', 'secret_b']`
     * instead of a `kid → secret` map). Without this guard the kids
     * would silently become `"0"` and `"1"`, producing meaningless
     * `kid` headers in issued tokens.
     *
     * @return void
     */
    public function testBuildKeyringRejectsIntegerIndexedKeys(): void
    {
        $config = new ConfigRepository([
            'laravel-authentication' => [
                'jwt' => [
                    'algorithm'  => 'HS256',
                    'secret'     => null,
                    'keys'       => ['secret_a', 'secret_b'],
                    'active_kid' => 'whatever',
                ],
            ],
        ]);

        $reflection = new \ReflectionClass(AuthServiceProvider::class);

        $build = $reflection->getMethod('buildKeyring');

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('non-string or empty kid');

        $build->invoke(null, $config, 'HS256');
    }

    /**
     * `buildKeyring` rejects a `jwt.keys` entry whose secret value is
     * `null` (typically because the env var backing it is unset). The
     * runtime guard must reject this before forwarding to the keyring
     * factory and the message must name the offending kid.
     *
     * @return void
     */
    public function testBuildKeyringRejectsNullSecretValue(): void
    {
        $config = new ConfigRepository([
            'laravel-authentication' => [
                'jwt' => [
                    'algorithm'  => 'HS256',
                    'secret'     => null,
                    'keys'       => [self::KID_NEW => null],
                    'active_kid' => self::KID_NEW,
                ],
            ],
        ]);

        $reflection = new \ReflectionClass(AuthServiceProvider::class);

        $build = $reflection->getMethod('buildKeyring');

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf('JWT key \'%s\'', self::KID_NEW));

        $build->invoke(null, $config, 'HS256');
    }

    /**
     * `buildKeyring` falls back to legacy single-secret mode when
     * `jwt.keys` is absent or empty: the resulting keyring reports
     * `null` from `activeKid()` (no header on issued tokens) and
     * `verificationKeys()` returns a single bare `Key`.
     *
     * @return void
     */
    public function testBuildKeyringFallsBackToLegacyModeWithoutKeys(): void
    {
        $config = new ConfigRepository([
            'laravel-authentication' => [
                'jwt' => [
                    'algorithm'  => 'HS256',
                    'secret'     => 'legacy-mode-secret-with-32-bytes!!',
                    'keys'       => [],
                    'active_kid' => '',
                ],
            ],
        ]);

        $reflection = new \ReflectionClass(AuthServiceProvider::class);

        $build = $reflection->getMethod('buildKeyring');

        /** @var \SineMacula\Laravel\Authentication\Jwt\JwtKeyring $keyring */
        $keyring = $build->invoke(null, $config, 'HS256');

        self::assertNull($keyring->activeKid());
        self::assertInstanceOf(\Firebase\JWT\Key::class, $keyring->verificationKeys());
    }

    /**
     * The `laravel-authentication-config` publish group is
     * registered with the framework's publish registry.
     *
     * @return void
     */
    public function testConfigPublishingTagIsRegistered(): void
    {
        self::assertContains(
            'laravel-authentication-config',
            ServiceProvider::publishableGroups(),
        );
    }

    /**
     * The `laravel-authentication-migrations` publish group is
     * registered with the framework's publish registry.
     *
     * @return void
     */
    public function testMigrationPublishingTagIsRegistered(): void
    {
        self::assertContains(
            'laravel-authentication-migrations',
            ServiceProvider::publishableGroups(),
        );
    }

    /**
     * The package `AuthManager` is a subclass of Laravel's framework
     * `AuthManager`. This is a sanity guard alongside the
     * `AuthManagerTest` assertion to ensure the service-provider
     * override does not regress to a sibling class.
     *
     * @return void
     */
    public function testResolvedAuthManagerExtendsFrameworkManager(): void
    {
        self::assertInstanceOf(IlluminateAuthManager::class, app('auth'));
    }

    /**
     * Register the package service provider against the Testbench
     * application.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthServiceProvider::class];
    }

    /**
     * Define the Testbench environment with package config and an
     * `auth.guards`/`auth.providers` setup that exercises both the
     * `model` user provider driver and the `jwt`/`basic` guard
     * driver creators.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('laravel-authentication.jwt.secret', self::JWT_SECRET);
        $config->set('laravel-authentication.jwt.algorithm', self::JWT_ALGORITHM);
        $config->set('laravel-authentication.jwt.access_ttl_minutes', self::JWT_TTL_MINUTES);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubAuthenticatableModel::class,
        ]);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.guards.cli', [
            'driver'   => 'basic',
            'provider' => 'identities',
        ]);
    }
}
