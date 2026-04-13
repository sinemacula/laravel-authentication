<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Feature tests for the guard-scoped `JwtTokenServiceFactory` and the
 * `Auth::jwt()` issuance surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthManager::class)]
#[CoversClass(JwtTokenServiceFactory::class)]
final class JwtTokenServiceFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Shared package-default secret used across the test cases. */
    private const string PACKAGE_SECRET = 'package-default-secret-with-32-bytes!';

    /** @var string Guard-scoped secret for the staff guard. */
    private const string STAFF_SECRET = 'staff-secret-with-at-least-32-bytes!!';

    /** @var string Guard-scoped secret for the customer guard. */
    private const string CUSTOMER_SECRET = 'customer-secret-with-32-bytes!!!!';

    /** @var string Kid used by the current-generation key in kid-mode tests. */
    private const string KID_NEW = '2026-04';

    /** @var string Kid used by the previous-generation key in kid-mode tests. */
    private const string KID_OLD = '2026-03';

    /**
     * `Auth::jwt()` resolves a service for the current default guard, so the
     * no-argument issuance API is still explicit about which guard it targets.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException|\ReflectionException
     */
    public function testAuthFacadeJwtUsesDefaultGuardConfig(): void
    {
        config()->set('auth.defaults.guard', 'package_default');

        $service = PackageAuth::jwt();

        self::assertInstanceOf(JwtTokenService::class, $service);
        self::assertSame('package-default-audience', $this->readServiceProperty($service, 'audience'));
        self::assertSame(45, $this->readServiceProperty($service, 'accessTtlMinutes'));
    }

    /**
     * `Auth::manager()->jwt('staff')` resolves the staff guard's override set,
     * not the package defaults or another guard's JWT config.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException|\ReflectionException
     */
    public function testAuthManagerJwtUsesNamedGuardSecretAndAudienceOverride(): void
    {
        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $service = $manager->jwt('staff');
        $keyring = $this->readServiceProperty($service, 'keyring');

        self::assertInstanceOf(JwtKeyring::class, $keyring);
        self::assertSame(self::STAFF_SECRET, $keyring->activeKey()->getKeyMaterial());
        self::assertSame('staff-api', $this->readServiceProperty($service, 'audience'));
    }

    /**
     * `Auth::jwt('customer')` resolves a distinct guard-scoped service, so
     * multi-guard apps do not share a context-free JWT issuer.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtUsesDistinctCustomerGuardOverride(): void
    {
        $service = PackageAuth::jwt('customer');
        $keyring = $this->readServiceProperty($service, 'keyring');

        self::assertInstanceOf(JwtKeyring::class, $keyring);
        self::assertSame(self::CUSTOMER_SECRET, $keyring->activeKey()->getKeyMaterial());
        self::assertSame('customer-api', $this->readServiceProperty($service, 'audience'));
    }

    /**
     * Guards with no `jwt` sub-block fall back cleanly to the package defaults,
     * preserving single-guard behaviour.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException|\ReflectionException
     */
    public function testAuthFacadeJwtFallsBackToPackageDefaultsWhenGuardHasNoJwtBlock(): void
    {
        $service = PackageAuth::jwt('package_default');
        $keyring = $this->readServiceProperty($service, 'keyring');

        self::assertInstanceOf(JwtKeyring::class, $keyring);
        self::assertSame(self::PACKAGE_SECRET, $keyring->activeKey()->getKeyMaterial());
        self::assertSame('package-default-audience', $this->readServiceProperty($service, 'audience'));
        self::assertSame(45, $this->readServiceProperty($service, 'accessTtlMinutes'));
    }

    /**
     * Kid-mode overrides are guard-scoped too, so one guard can rotate keys
     * independently of the package defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException|\ReflectionException
     */
    public function testAuthFacadeJwtHonoursGuardKidOverride(): void
    {
        $service = PackageAuth::jwt('rotating');
        $keyring = $this->readServiceProperty($service, 'keyring');

        self::assertInstanceOf(JwtKeyring::class, $keyring);
        self::assertSame(self::KID_NEW, $keyring->activeKid());

        $verificationKeys = $keyring->verificationKeys();

        self::assertIsArray($verificationKeys);
        self::assertArrayHasKey(self::KID_NEW, $verificationKeys);
        self::assertArrayHasKey(self::KID_OLD, $verificationKeys);
    }

    /**
     * When a PSR-3 logger is bound, the factory forwards it into the built
     * service instead of falling back to `NullLogger`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException|\ReflectionException
     */
    public function testAuthFacadeJwtUsesBoundLoggerWhenAvailable(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);

        $this->app?->instance(LoggerInterface::class, $logger);

        $service = PackageAuth::jwt('staff');

        self::assertSame($logger, $this->readServiceProperty($service, 'logger'));
    }

    /**
     * Non-JWT guards are rejected up front so the issuance API cannot be used
     * against the basic driver.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtRejectsNonJwtGuard(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('does not use the jwt driver');

        PackageAuth::jwt('cli');
    }

    /**
     * Unknown guard names are rejected clearly instead of falling back to a
     * context-free service.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtRejectsUnknownGuard(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('is not configured');

        PackageAuth::jwt('missing');
    }

    /**
     * Integer-indexed key lists are rejected so guard-local kid mode still
     * fails closed on malformed config.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtRejectsIntegerIndexedKeys(): void
    {
        config()->set('auth.guards.broken_keys', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'       => ['secret_a', 'secret_b'],
                'active_kid' => 'whatever',
            ],
        ]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('non-string or empty kid');

        PackageAuth::jwt('broken_keys');
    }

    /**
     * Null secret material inside a kid map is rejected before the keyring is
     * built, and the error names the offending kid.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtRejectsNullSecretValue(): void
    {
        config()->set('auth.guards.null_secret', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'       => [self::KID_NEW => null],
                'active_kid' => self::KID_NEW,
            ],
        ]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf('JWT key \'%s\'', self::KID_NEW));

        PackageAuth::jwt('null_secret');
    }

    /**
     * `forGuard()` rejects an empty guard name with an
     * `InvalidArgumentException`. Pins the `$guard === ''` early-throw.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForGuardRejectsEmptyGuardName(): void
    {
        /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory $factory */
        $factory = app(JwtTokenServiceFactory::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('non-empty guard name');

        $factory->forGuard('');
    }

    /**
     * Per-guard integer JWT config overrides (e.g. `access_ttl_minutes`)
     * are honoured over the package defaults. Pins the guard-level int
     * return in `resolveJwtInteger()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException|\ReflectionException
     */
    public function testForGuardHonoursPerGuardIntegerOverride(): void
    {
        config()->set('auth.guards.int_override', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'secret'             => self::STAFF_SECRET,
                'access_ttl_minutes' => 99,
            ],
        ]);

        $service = PackageAuth::jwt('int_override');

        self::assertSame(99, $this->readServiceProperty($service, 'accessTtlMinutes'));
    }

    /**
     * When the PSR-3 logger is not bound in the container, the factory
     * returns null so the JWT service uses its NullLogger fallback. Pins
     * the `!$this->app->bound(LoggerInterface::class)` return path.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testForGuardReturnsNullLoggerWhenNotBound(): void
    {
        // Use a fresh Application container without any logger binding
        // to exercise the resolveOptionalLogger() null branch.
        $bareApp = \Mockery::mock(Application::class)->makePartial();
        $bareApp->shouldReceive('bound')
            ->with(LoggerInterface::class)
            ->andReturnFalse();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(\Illuminate\Config\Repository::class);

        $factory = new JwtTokenServiceFactory($bareApp, $config);

        $service = $factory->forGuard('staff');

        self::assertInstanceOf(
            \Psr\Log\NullLogger::class,
            $this->readServiceProperty($service, 'logger'),
        );
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
     * Define the default package JWT config plus several guards that exercise
     * guard-scoped service resolution.
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

        $config->set('auth.defaults.guard', 'package_default');

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubAuthenticatableModel::class,
        ]);

        $this->configureGuards($config);
        $this->configurePackageDefaults($config);
    }

    /**
     * Read a private property off a `JwtTokenService` instance via reflection.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $service
     * @param  string  $property
     * @return mixed
     *
     * @throws \ReflectionException
     *
     * @SuppressWarnings("php:S3011")
     */
    private function readServiceProperty(JwtTokenService $service, string $property): mixed
    {
        $reflectionProperty = (new \ReflectionClass($service))->getProperty($property);

        return $reflectionProperty->getValue($service);
    }

    /**
     * Register the per-guard auth config blocks.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    private function configureGuards(ConfigRepository $config): void
    {
        $config->set('auth.guards.package_default', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.guards.staff', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'secret'   => self::STAFF_SECRET,
                'audience' => 'staff-api',
            ],
        ]);

        $config->set('auth.guards.customer', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'secret'   => self::CUSTOMER_SECRET,
                'audience' => 'customer-api',
            ],
        ]);

        $config->set('auth.guards.rotating', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys' => [
                    self::KID_NEW => 'kid-new-secret-material-32-bytes!!',
                    self::KID_OLD => 'kid-old-secret-material-32-bytes!!',
                ],
                'active_kid' => self::KID_NEW,
            ],
        ]);

        $config->set('auth.guards.cli', [
            'driver'   => 'basic',
            'provider' => 'identities',
        ]);
    }

    /**
     * Set the package-wide JWT defaults.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    private function configurePackageDefaults(ConfigRepository $config): void
    {
        $config->set('authentication.jwt.secret', self::PACKAGE_SECRET);
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.audience', 'package-default-audience');
        $config->set('authentication.jwt.access_ttl_minutes', 45);
    }
}
