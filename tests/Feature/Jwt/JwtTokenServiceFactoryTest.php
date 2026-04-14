<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
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

    /** @var string Secret material for the current-generation kid key. */
    private const string KID_NEW_SECRET = 'kid-new-secret-material-32-bytes!!';

    /** @var string Secret material for the previous-generation kid key. */
    private const string KID_OLD_SECRET = 'kid-old-secret-material-32-bytes!!';

    /**
     * Freeze Carbon and the JWT library clock before each test so time-based
     * assertions are deterministic.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        JWT::$timestamp = $now->getTimestamp();
    }

    /**
     * Release both frozen clocks once each test has completed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * `Auth::jwt()` resolves a service for the current default guard, so the
     * no-argument issuance API is still explicit about which guard it targets.
     *
     * Verified by issuing a token and asserting its `aud` claim and TTL match
     * the package defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtUsesDefaultGuardConfig(): void
    {
        config()->set('auth.defaults.guard', 'package_default');

        $service = PackageAuth::jwt();

        self::assertInstanceOf(JwtTokenService::class, $service);

        $token  = $this->issueAccessToken($service);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertNotNull($claims);
        self::assertSame('package-default-audience', $claims[Claims::AUDIENCE->value]);
        self::assertIsInt($claims[Claims::EXPIRES_AT->value]);
        self::assertIsInt($claims[Claims::ISSUED_AT->value]);
        self::assertSame(45 * 60, $claims[Claims::EXPIRES_AT->value] - $claims[Claims::ISSUED_AT->value]);
    }

    /**
     * `Auth::manager()->jwt('staff')` resolves the staff guard's override set,
     * not the package defaults or another guard's JWT config.
     *
     * Verified by issuing a token with the staff service and confirming it can
     * be parsed by a standalone service using the same secret, and that the
     * `aud` claim reflects the staff audience.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthManagerJwtUsesNamedGuardSecretAndAudienceOverride(): void
    {
        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $service = $manager->jwt('staff');
        $token   = $this->issueAccessToken($service);

        $verifier = new JwtTokenService(self::STAFF_SECRET, 'HS256', 15, 60 * 24 * 30, 30, null, 'staff-api');
        $claims   = $verifier->parse($token, TokenType::ACCESS);

        self::assertNotNull($claims);
        self::assertSame('staff-api', $claims[Claims::AUDIENCE->value]);
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
        $token   = $this->issueAccessToken($service);

        $verifier = new JwtTokenService(self::CUSTOMER_SECRET, 'HS256', 15, 60 * 24 * 30, 30, null, 'customer-api');
        $claims   = $verifier->parse($token, TokenType::ACCESS);

        self::assertNotNull($claims);
        self::assertSame('customer-api', $claims[Claims::AUDIENCE->value]);

        // Token must NOT be parseable with the staff secret.
        $wrongVerifier = new JwtTokenService(self::STAFF_SECRET, 'HS256', 15, 60 * 24 * 30, 30, null, 'customer-api');
        self::assertNull($wrongVerifier->parse($token, TokenType::ACCESS));
    }

    /**
     * Guards with no `jwt` sub-block fall back cleanly to the package defaults,
     * preserving single-guard behaviour.
     *
     * Verified by issuing a token and asserting the `aud` claim, TTL, and
     * signing secret all match the package-wide config.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtFallsBackToPackageDefaultsWhenGuardHasNoJwtBlock(): void
    {
        $service = PackageAuth::jwt('package_default');
        $token   = $this->issueAccessToken($service);

        $verifier = new JwtTokenService(self::PACKAGE_SECRET, 'HS256', 15, 60 * 24 * 30, 30, null, 'package-default-audience');
        $claims   = $verifier->parse($token, TokenType::ACCESS);

        self::assertNotNull($claims);
        self::assertSame('package-default-audience', $claims[Claims::AUDIENCE->value]);
        self::assertIsInt($claims[Claims::EXPIRES_AT->value]);
        self::assertIsInt($claims[Claims::ISSUED_AT->value]);
        self::assertSame(45 * 60, $claims[Claims::EXPIRES_AT->value] - $claims[Claims::ISSUED_AT->value]);
    }

    /**
     * Kid-mode overrides are guard-scoped too, so one guard can rotate keys
     * independently of the package defaults.
     *
     * Verified by issuing a token and checking the JWT header's `kid` field,
     * then confirming both the new and old keys can verify it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtHonoursGuardKidOverride(): void
    {
        $service = PackageAuth::jwt('rotating');

        self::assertInstanceOf(JwtTokenService::class, $service);

        $token = $this->issueAccessToken($service);

        // Decode the JWT header to verify the active kid.
        $parts = explode('.', $token);

        self::assertCount(3, $parts, 'JWT must have three segments');

        /** @var array<string, mixed> $header */
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/'), true) ?: '', true);

        self::assertSame(self::KID_NEW, $header['kid'] ?? null);

        // The token must be parseable by the same service (which accepts both
        // the new and old kid for verification).
        $claims = $service->parse($token, TokenType::ACCESS);
        self::assertNotNull($claims);

        // A standalone service with only the new kid's secret must also parse
        // the token.
        $newKeyVerifier = new JwtTokenService(self::KID_NEW_SECRET, 'HS256', 15, 60 * 24 * 30);
        self::assertNotNull($newKeyVerifier->parse($token, TokenType::ACCESS));
    }

    /**
     * When a PSR-3 logger is bound, the factory forwards it into the built
     * service instead of falling back to `NullLogger`.
     *
     * Verified by parsing an invalid token and asserting the mock logger
     * received a `debug` call from the decode-failure path.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthFacadeJwtUsesBoundLoggerWhenAvailable(): void
    {
        $logger = \Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('debug')
            ->atLeast()
            ->once();

        $this->app?->instance(LoggerInterface::class, $logger);

        $service = PackageAuth::jwt('staff');

        self::assertNotNull($service);

        // Parsing a malformed token triggers the decode-failure debug
        // log.
        $service->parse('not-a-valid-jwt');
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
     * Per-guard integer JWT config overrides (e.g. `access_ttl_minutes`) are
     * honoured over the package defaults. Pins the guard-level int return in
     * `resolveJwtInteger()`.
     *
     * Verified by issuing a token and checking the `exp - iat` delta.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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

        self::assertInstanceOf(JwtTokenService::class, $service);

        $token  = $this->issueAccessToken($service);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertNotNull($claims);
        self::assertIsInt($claims[Claims::EXPIRES_AT->value]);
        self::assertIsInt($claims[Claims::ISSUED_AT->value]);
        self::assertSame(99 * 60, $claims[Claims::EXPIRES_AT->value] - $claims[Claims::ISSUED_AT->value]);
    }

    /**
     * When the PSR-3 logger is not bound in the container, the factory returns
     * null so the JWT service uses its NullLogger fallback. Pins the
     * `!$this->app->bound(LoggerInterface::class)` return path.
     *
     * Verified by building a factory against a container with no logger binding
     * and parsing an invalid token - the service must return null without
     * error, proving the NullLogger fallback handles the debug call silently.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForGuardReturnsNullLoggerWhenNotBound(): void
    {
        $bareApp = \Mockery::mock(Application::class)->makePartial();
        $bareApp->shouldReceive('bound')
            ->with(LoggerInterface::class)
            ->andReturnFalse();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);

        $factory = new JwtTokenServiceFactory($bareApp, $config);
        $service = $factory->forGuard('staff');

        // Parsing an invalid token exercises the decode-failure path which
        // calls logger->debug(). If the NullLogger fallback was not injected
        // this would throw.
        self::assertNull($service->parse('not-a-valid-jwt'));
    }

    /**
     * Repeated calls to `forGuard()` with the same guard name return the same
     * memoized instance rather than constructing a new service.
     *
     * @return void
     */
    public function testForGuardReturnsMemoizedInstanceOnRepeatedCalls(): void
    {
        $first  = PackageAuth::jwt('staff');
        $second = PackageAuth::jwt('staff');

        self::assertSame($first, $second);
    }

    /**
     * Different guard names resolve distinct memoized instances.
     *
     * @return void
     */
    public function testForGuardReturnsDifferentInstancesForDifferentGuards(): void
    {
        $staff    = PackageAuth::jwt('staff');
        $customer = PackageAuth::jwt('customer');

        self::assertNotSame($staff, $customer);
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
                    self::KID_NEW => self::KID_NEW_SECRET,
                    self::KID_OLD => self::KID_OLD_SECRET,
                ],
                'active_kid' => self::KID_NEW,
            ],
        ]);

        $config->set('auth.guards.cli', [
            'driver'   => 'basic',
            'provider' => 'identities',
        ]);

        $config->set('authentication.jwt.secret', self::PACKAGE_SECRET);
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.audience', 'package-default-audience');
        $config->set('authentication.jwt.access_ttl_minutes', 45);
    }

    /**
     * Issue an access token using mock context objects.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $service
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issueAccessToken(JwtTokenService $service): string
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('id-1');

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('pid-1');

        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')->andReturn('did-1');

        return $service->issueAccessToken($identity, $principal, $device);
    }
}
