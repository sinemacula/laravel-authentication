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
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use Tests\Concerns\InteractsWithJwtTokens;
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
    use InteractsWithJwtTokens, MockeryPHPUnitIntegration;

    /** @var string Shared package-default secret used across the test cases. */
    private const string PACKAGE_SECRET = 'package-default-secret-with-32-bytes!';

    /** @var string Kid the package-default secret is registered under. */
    private const string PACKAGE_KID = 'default';

    /** @var string Kid the staff guard's secret is registered under. */
    private const string STAFF_KID = 'staff';

    /** @var string Kid the customer guard's secret is registered under. */
    private const string CUSTOMER_KID = 'customer';

    /** @var string Guard-scoped secret for the staff guard. */
    private const string STAFF_SECRET = 'staff-secret-with-at-least-32-bytes!!';

    /** @var string Guard-scoped secret for the customer guard. */
    private const string CUSTOMER_SECRET = 'customer-secret-with-32-bytes!!!!';

    /** @var string Kid used by the current-generation key in rotation tests. */
    private const string KID_NEW = '2026-04';

    /** @var string Kid used by the previous-generation key in rotation tests. */
    private const string KID_OLD = '2026-03';

    /** @var string Secret material for the current-generation kid key. */
    private const string KID_NEW_SECRET = 'kid-new-secret-material-32-bytes!!';

    /** @var string Secret material for the previous-generation kid key. */
    private const string KID_OLD_SECRET = 'kid-old-secret-material-32-bytes!!';

    /** @var string Purely numeric kid for the current-generation key. */
    private const string NUMERIC_KID_NEW = '2026';

    /** @var string Purely numeric kid for the previous-generation key. */
    private const string NUMERIC_KID_OLD = '2025';

    /** @var string Secret material long enough for HS384 (48 bytes). */
    private const string HS384_SECRET = 'hs384-secret-material-with-at-least-48-bytes!!!!';

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
     * @throws \Random\RandomException
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
     * be parsed by a standalone service using the same kid and secret, and that
     * the `aud` claim reflects the staff audience.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAuthManagerJwtUsesNamedGuardSecretAndAudienceOverride(): void
    {
        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $service = $manager->jwt('staff');
        $token   = $this->issueAccessToken($service);

        $verifier = $this->makeVerifier([self::STAFF_KID => self::STAFF_SECRET], 'staff-api');
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
     * @throws \Random\RandomException
     */
    public function testAuthFacadeJwtUsesDistinctCustomerGuardOverride(): void
    {
        $service = PackageAuth::jwt('customer');
        $token   = $this->issueAccessToken($service);

        $verifier = $this->makeVerifier([self::CUSTOMER_KID => self::CUSTOMER_SECRET], 'customer-api');
        $claims   = $verifier->parse($token, TokenType::ACCESS);

        self::assertNotNull($claims);
        self::assertSame('customer-api', $claims[Claims::AUDIENCE->value]);

        // Token must NOT be parseable with the staff secret.
        $wrongVerifier = $this->makeVerifier([self::CUSTOMER_KID => self::STAFF_SECRET], 'customer-api');
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
     * @throws \Random\RandomException
     */
    public function testAuthFacadeJwtFallsBackToPackageDefaultsWhenGuardHasNoJwtBlock(): void
    {
        $service = PackageAuth::jwt('package_default');
        $token   = $this->issueAccessToken($service);

        $verifier = $this->makeVerifier([self::PACKAGE_KID => self::PACKAGE_SECRET], 'package-default-audience');
        $claims   = $verifier->parse($token, TokenType::ACCESS);

        self::assertNotNull($claims);
        self::assertSame('package-default-audience', $claims[Claims::AUDIENCE->value]);
        self::assertIsInt($claims[Claims::EXPIRES_AT->value]);
        self::assertIsInt($claims[Claims::ISSUED_AT->value]);
        self::assertSame(45 * 60, $claims[Claims::EXPIRES_AT->value] - $claims[Claims::ISSUED_AT->value]);
    }

    /**
     * Key-map overrides are guard-scoped too, so one guard can rotate keys
     * independently of the package defaults.
     *
     * Verified by issuing a token and checking the JWT header's `kid` field,
     * then confirming both the new and old keys can verify it.
     *
     * @return void
     *
     * @throws \Random\RandomException
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
        $newKeyVerifier = $this->makeVerifier([self::KID_NEW => self::KID_NEW_SECRET]);
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

        // Parsing a malformed token triggers the decode-failure debug log.
        $service->parse('not-a-valid-jwt');
    }

    /**
     * Non-JWT guards are rejected up front so the issuance API cannot be used
     * against another driver such as Laravel's `session` guard.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsNonJwtGuard(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('does not use the jwt driver');

        PackageAuth::jwt('web');
    }

    /**
     * Unknown guard names are rejected clearly instead of falling back to a
     * context-free service.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsUnknownGuard(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('is not configured');

        PackageAuth::jwt('missing');
    }

    /**
     * An integer-indexed key list still fails closed: its kids are `0` and `1`,
     * so an active kid naming anything else is not found in the map.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsIntegerIndexedKeysWithoutMatchingActiveKid(): void
    {
        config()->set('auth.guards.broken_keys', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'       => [self::STAFF_SECRET, self::CUSTOMER_SECRET],
                'active_kid' => 'whatever',
            ],
        ]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT active kid \'whatever\' is not present in the configured key map.');

        PackageAuth::jwt('broken_keys');
    }

    /**
     * A purely numeric kid (which PHP stores as an integer array key) signs and
     * verifies like any other kid, including a numeric kid kept only for
     * verification during rotation.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAuthFacadeJwtAcceptsNumericKids(): void
    {
        config()->set('auth.guards.numeric_kids', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys' => [
                    self::NUMERIC_KID_NEW => self::KID_NEW_SECRET,
                    self::NUMERIC_KID_OLD => self::KID_OLD_SECRET,
                ],
                'active_kid' => self::NUMERIC_KID_NEW,
            ],
        ]);

        $service = PackageAuth::jwt('numeric_kids');

        self::assertInstanceOf(JwtTokenService::class, $service);

        $token = $this->issueAccessToken($service);

        self::assertSame(self::NUMERIC_KID_NEW, $this->jwtHeader($token)['kid'] ?? null);
        self::assertNotNull($service->parse($token, TokenType::ACCESS));

        $oldToken = $this->issueAccessToken(
            $this->makeVerifier([self::NUMERIC_KID_OLD => self::KID_OLD_SECRET], 'package-default-audience'),
        );

        self::assertSame(self::NUMERIC_KID_OLD, $this->jwtHeader($oldToken)['kid'] ?? null);
        self::assertNotNull($service->parse($oldToken, TokenType::ACCESS));
    }

    /**
     * Null secret material inside a kid map is rejected before the keyring is
     * built, and the error names the offending kid.
     *
     * @return void
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
     * A guard `keys` override that is not a map (for example a bare secret
     * string) is rejected instead of being treated as a single key.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsNonArrayGuardKeys(): void
    {
        config()->set('auth.guards.string_keys', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'       => self::STAFF_SECRET,
                'active_kid' => self::STAFF_KID,
            ],
        ]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(
            'JWT keys must be a kid -> secret map. Set `authentication.jwt.keys`'
            . ' (or the guard\'s `jwt.keys` override) to an array of at least one entry.',
        );

        PackageAuth::jwt('string_keys');
    }

    /**
     * A missing package-wide key map is rejected for guards that do not
     * override it, so there is no keyless fallback.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsMissingPackageKeys(): void
    {
        config()->set('authentication.jwt.keys', null);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(
            'JWT keys must be a kid -> secret map. Set `authentication.jwt.keys`'
            . ' (or the guard\'s `jwt.keys` override) to an array of at least one entry.',
        );

        PackageAuth::jwt('package_default');
    }

    /**
     * An empty guard key map is rejected rather than falling back to the
     * package-wide keys.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsEmptyGuardKeys(): void
    {
        config()->set('auth.guards.empty_keys', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'       => [],
                'active_kid' => self::STAFF_KID,
            ],
        ]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT key map is empty. Set `authentication.jwt.keys` to a kid -> secret map of at least one entry.');

        PackageAuth::jwt('empty_keys');
    }

    /**
     * A guard that overrides only `active_kid` signs with that kid from the
     * package-wide key map.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAuthFacadeJwtUsesGuardActiveKidAgainstPackageKeys(): void
    {
        config()->set('authentication.jwt.keys', [
            self::PACKAGE_KID => self::PACKAGE_SECRET,
            self::KID_NEW     => self::KID_NEW_SECRET,
        ]);

        config()->set('auth.guards.active_kid_only', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'active_kid' => self::KID_NEW,
            ],
        ]);

        $token = $this->issueAccessToken(PackageAuth::jwt('active_kid_only'));

        $newKeyVerifier   = $this->makeVerifier([self::KID_NEW => self::KID_NEW_SECRET], 'package-default-audience');
        $wrongKeyVerifier = $this->makeVerifier([self::KID_NEW => self::PACKAGE_SECRET], 'package-default-audience');

        self::assertNotNull($newKeyVerifier->parse($token, TokenType::ACCESS));
        self::assertNull($wrongKeyVerifier->parse($token, TokenType::ACCESS));
    }

    /**
     * A guard that overrides only `active_kid` with a purely numeric kid
     * written as an integer signs with that kid from the package-wide key map
     * instead of falling back to the package-wide active kid.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAuthFacadeJwtResolvesIntegerGuardActiveKidAgainstPackageKeys(): void
    {
        config()->set('authentication.jwt.keys', [
            self::PACKAGE_KID     => self::PACKAGE_SECRET,
            self::NUMERIC_KID_NEW => self::KID_NEW_SECRET,
        ]);

        config()->set('auth.guards.integer_active_kid', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'active_kid' => (int) self::NUMERIC_KID_NEW,
            ],
        ]);

        $token = $this->issueAccessToken(PackageAuth::jwt('integer_active_kid'));

        $verifier = $this->makeVerifier([self::NUMERIC_KID_NEW => self::KID_NEW_SECRET], 'package-default-audience');

        self::assertSame(self::NUMERIC_KID_NEW, $this->jwtHeader($token)['kid'] ?? null);
        self::assertNotNull($verifier->parse($token, TokenType::ACCESS));
    }

    /**
     * A package-wide `active_kid` written as an integer resolves to its string
     * form rather than failing on the config repository's string accessor.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAuthFacadeJwtResolvesIntegerPackageActiveKid(): void
    {
        config()->set('authentication.jwt.keys', [self::NUMERIC_KID_NEW => self::KID_NEW_SECRET]);
        config()->set('authentication.jwt.active_kid', (int) self::NUMERIC_KID_NEW);

        $token = $this->issueAccessToken(PackageAuth::jwt('package_default'));

        self::assertSame(self::NUMERIC_KID_NEW, $this->jwtHeader($token)['kid'] ?? null);
    }

    /**
     * A guard `active_kid` that is neither a string nor an integer fails closed
     * with the typed configuration exception instead of silently falling back
     * to the package-wide active kid.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsNonStringGuardActiveKid(): void
    {
        config()->set('auth.guards.boolean_active_kid', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'active_kid' => true,
            ],
        ]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(
            'JWT active kid is missing or not a string. Set `authentication.jwt.active_kid` (or the guard\'s'
            . ' `jwt.active_kid` override) to a kid in the key map.',
        );

        PackageAuth::jwt('boolean_active_kid');
    }

    /**
     * A missing package-wide `active_kid` fails closed with the typed
     * configuration exception.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsMissingPackageActiveKid(): void
    {
        config()->set('authentication.jwt.active_kid', null);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT active kid is missing or not a string.');

        PackageAuth::jwt('package_default');
    }

    /**
     * A key shorter than the algorithm's minimum fails guard resolution with
     * the typed configuration exception instead of failing on first use.
     *
     * @return void
     */
    public function testAuthFacadeJwtRejectsKeyShorterThanAlgorithmMinimum(): void
    {
        config()->set('auth.guards.short_key', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'       => [self::STAFF_KID => self::STAFF_SECRET],
                'active_kid' => self::STAFF_KID,
                'algorithm'  => 'HS512',
            ],
        ]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf('JWT key \'%s\' is too short for HS512: it must be at least 64 bytes.', self::STAFF_KID));

        PackageAuth::jwt('short_key');
    }

    /**
     * A guard's `jwt.algorithm` override reaches signing through the keyring:
     * the issued token names that algorithm in its header and verifies under
     * the same service.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAuthFacadeJwtSignsWithGuardAlgorithmOverride(): void
    {
        config()->set('auth.guards.hs384', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'       => [self::STAFF_KID => self::HS384_SECRET],
                'active_kid' => self::STAFF_KID,
                'algorithm'  => 'HS384',
            ],
        ]);

        $service = PackageAuth::jwt('hs384');

        self::assertInstanceOf(JwtTokenService::class, $service);

        $token = $this->issueAccessToken($service);

        self::assertSame('HS384', $this->jwtHeader($token)['alg'] ?? null);
        self::assertNotNull($service->parse($token, TokenType::ACCESS));
    }

    /**
     * `forGuard()` rejects an empty guard name with an
     * `InvalidArgumentException`. Pins the `$guard === ''` early-throw.
     *
     * @return void
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
     * @throws \Random\RandomException
     */
    public function testForGuardHonoursPerGuardIntegerOverride(): void
    {
        config()->set('auth.guards.int_override', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'               => [self::STAFF_KID => self::STAFF_SECRET],
                'active_kid'         => self::STAFF_KID,
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
        return [AuthenticationServiceProvider::class];
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
                'keys'       => [self::STAFF_KID => self::STAFF_SECRET],
                'active_kid' => self::STAFF_KID,
                'audience'   => 'staff-api',
            ],
        ]);

        $config->set('auth.guards.customer', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'keys'       => [self::CUSTOMER_KID => self::CUSTOMER_SECRET],
                'active_kid' => self::CUSTOMER_KID,
                'audience'   => 'customer-api',
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

        $config->set('auth.guards.web', [
            'driver'   => 'session',
            'provider' => 'identities',
        ]);

        $config->set('authentication.jwt.keys', [self::PACKAGE_KID => self::PACKAGE_SECRET]);
        $config->set('authentication.jwt.active_kid', self::PACKAGE_KID);
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.issuer', null);
        $config->set('authentication.jwt.audience', 'package-default-audience');
        $config->set('authentication.jwt.access_ttl_minutes', 45);
    }

    /**
     * Build a standalone verifier over the supplied key map, using its first
     * kid as the active kid.
     *
     * @param  array<string, string>  $keys
     * @param  ?string  $audience
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function makeVerifier(#[\SensitiveParameter] array $keys, ?string $audience = null): JwtTokenService
    {
        return new JwtTokenService(
            JwtKeyring::fromKeyMap($keys, (string) array_key_first($keys), 'HS256'),
            15,
            60 * 24 * 30,
            30,
            null,
            $audience,
        );
    }
}
