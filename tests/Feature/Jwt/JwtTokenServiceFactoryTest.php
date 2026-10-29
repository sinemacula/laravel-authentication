<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
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

    /** @var string Guard whose lifetimes and leeway the resolution tests read. */
    private const string LIFETIME_GUARD = 'package_default';

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

        $verifier = $this->makeVerifier('staff', [self::STAFF_KID => self::STAFF_SECRET], 'staff-api');
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

        $verifier = $this->makeVerifier('customer', [self::CUSTOMER_KID => self::CUSTOMER_SECRET], 'customer-api');
        $claims   = $verifier->parse($token, TokenType::ACCESS);

        self::assertNotNull($claims);
        self::assertSame('customer-api', $claims[Claims::AUDIENCE->value]);

        $wrongVerifier = $this->makeVerifier('customer', [self::CUSTOMER_KID => self::STAFF_SECRET], 'customer-api');
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

        $verifier = $this->makeVerifier('package_default', [self::PACKAGE_KID => self::PACKAGE_SECRET], 'package-default-audience');
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

        self::assertSame(self::KID_NEW, $this->jwtHeader($token)['kid'] ?? null);

        $claims = $service->parse($token, TokenType::ACCESS);
        self::assertNotNull($claims);

        $newKeyVerifier = $this->makeVerifier('rotating', [self::KID_NEW => self::KID_NEW_SECRET]);
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
            $this->makeVerifier('numeric_kids', [self::NUMERIC_KID_OLD => self::KID_OLD_SECRET], 'package-default-audience'),
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

        $newKeyVerifier   = $this->makeVerifier('active_kid_only', [self::KID_NEW => self::KID_NEW_SECRET], 'package-default-audience');
        $wrongKeyVerifier = $this->makeVerifier('active_kid_only', [self::KID_NEW => self::PACKAGE_SECRET], 'package-default-audience');

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

        $verifier = $this->makeVerifier('integer_active_kid', [self::NUMERIC_KID_NEW => self::KID_NEW_SECRET], 'package-default-audience');

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
     * A guard `active_kid` override of `null` is treated as absent and falls
     * back to the package-wide active kid instead of failing closed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAuthFacadeJwtFallsBackToPackageActiveKidForNullGuardOverride(): void
    {
        config()->set('auth.guards.null_active_kid', [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'active_kid' => null,
            ],
        ]);

        $token = $this->issueAccessToken(PackageAuth::jwt('null_active_kid'));

        $verifier = $this->makeVerifier('null_active_kid', [self::PACKAGE_KID => self::PACKAGE_SECRET], 'package-default-audience');

        self::assertSame(self::PACKAGE_KID, $this->jwtHeader($token)['kid'] ?? null);
        self::assertNotNull($verifier->parse($token, TokenType::ACCESS));
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
            'JWT active kid is missing or not a string or integer. Set `authentication.jwt.active_kid` (or the'
            . ' guard\'s `jwt.active_kid` override) to a kid in the key map.',
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
        $this->expectExceptionMessage('JWT active kid is missing or not a string or integer.');

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
     * Rows of `[key, a valid value other than the default]` for every integer
     * key.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideIntegerKeys(): iterable
    {
        yield from [
            'access lifetime'   => ['access_ttl_minutes', 12],
            'idle lifetime'     => ['refresh_idle_ttl_minutes', 1234],
            'absolute lifetime' => ['refresh_absolute_ttl_minutes', 5678],
            'grace window'      => ['refresh_grace_seconds', 45],
            'leeway'            => ['leeway_seconds', 7],
        ];
    }

    /**
     * A guard override that is present and not `null` wins over the package
     * value.
     *
     * @param  string  $key
     * @param  int  $value
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideIntegerKeys')]
    public function testGuardOverrideWins(string $key, int $value): void
    {
        $this->setGuardOverrides([$key => $value]);

        self::assertSame($value, $this->resolved($key));
    }

    /**
     * Without an override, or with a `null` one, the package value applies.
     *
     * @param  string  $key
     * @param  int  $value
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideIntegerKeys')]
    public function testPackageValueAppliesWithoutAnOverride(string $key, int $value): void
    {
        config()->set("authentication.jwt.{$key}", $value);

        self::assertSame($value, $this->resolved($key));

        $this->setGuardOverrides([$key => null]);

        self::assertSame($value, $this->resolved($key));
    }

    /**
     * A string of digits, which is what `env()` returns, is read as its integer
     * at either level.
     *
     * @param  string  $key
     * @param  int  $value
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideIntegerKeys')]
    public function testCanonicalDigitStringIsAccepted(string $key, int $value): void
    {
        config()->set("authentication.jwt.{$key}", (string) $value);

        self::assertSame($value, $this->resolved($key));

        $this->setGuardOverrides([$key => (string) ($value + 1)]);

        self::assertSame($value + 1, $this->resolved($key));
    }

    /**
     * Values that are neither an integer nor a canonical digit string.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedValues(): iterable
    {
        yield from [
            'true'                => [true],
            'float'               => [1.0],
            'decimal string'      => ['1.0'],
            'padded with a space' => [' 5'],
            'signed'              => ['-1'],
            'leading zero'        => ['05'],
            'letters'             => ['five'],
            'empty string'        => [''],
            'overflowing digits'  => ['99999999999999999999'],
            'array'               => [[5]],
        ];
    }

    /**
     * A guard override that is not an integer fails closed rather than being
     * ignored, naming the key and the guard.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testMalformedGuardOverrideFailsClosed(mixed $value): void
    {
        $this->setGuardOverrides(['access_ttl_minutes' => $value]);

        $this->expectInvalidKey('access_ttl_minutes', 1, 1440);

        $this->lifetimeService();
    }

    /**
     * A package value that is not an integer, `null` included, fails closed.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testMalformedPackageValueFailsClosed(mixed $value): void
    {
        config()->set('authentication.jwt.refresh_idle_ttl_minutes', $value);

        $this->expectInvalidKey('refresh_idle_ttl_minutes', 1, 5256000);

        $this->lifetimeService();
    }

    /**
     * Rows of `[key, value, minimum, maximum, accepted]` at and beyond each
     * range bound.
     *
     * @return iterable<string, array{0: string, 1: int, 2: int, 3: int, 4: bool}>
     */
    public static function provideRangeBounds(): iterable
    {
        $ranges = [
            ['access_ttl_minutes', 1, 1440],
            ['refresh_idle_ttl_minutes', 1, 5256000],
            ['refresh_absolute_ttl_minutes', 1, 5256000],
            ['refresh_grace_seconds', 0, 300],
            ['leeway_seconds', 0, 300],
        ];

        foreach ($ranges as [$key, $min, $max]) {
            yield "{$key} below the minimum" => [$key, $min - 1, $min, $max, false];
            yield "{$key} at the minimum" => [$key, $min, $min, $max, true];
            yield "{$key} at the maximum" => [$key, $max, $min, $max, true];
            yield "{$key} above the maximum" => [$key, $max + 1, $min, $max, false];
        }
    }

    /**
     * Each key accepts exactly its range: no lifetime of zero, at most a day
     * for access tokens and ten years for sessions, and at most five minutes of
     * leeway.
     *
     * @param  string  $key
     * @param  int  $value
     * @param  int  $min
     * @param  int  $max
     * @param  bool  $accepted
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRangeBounds')]
    public function testEachKeyAcceptsExactlyItsRange(string $key, int $value, int $min, int $max, bool $accepted): void
    {
        $this->setGuardOverrides([$key => $value]);

        if (!$accepted) {
            $this->expectInvalidKey($key, $min, $max);
        }

        self::assertSame($value, $this->resolved($key));
    }

    /**
     * Rows of `[key]` for every integer key.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideIntegerKeyNames(): iterable
    {
        foreach (self::provideIntegerKeys() as $name => [$key]) {
            yield $name => [$key];
        }
    }

    /**
     * A key missing at both levels fails closed: the factory carries no literal
     * default of its own.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideIntegerKeyNames')]
    public function testKeyMissingAtBothLevelsFailsClosed(string $key): void
    {
        $this->removePackageValue($key);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage("JWT `{$key}` for guard [" . self::LIFETIME_GUARD . ']');

        $this->lifetimeService();
    }

    /**
     * An algorithm missing at both levels fails closed instead of defaulting to
     * HS256.
     *
     * @return void
     */
    public function testAlgorithmMissingAtBothLevelsFailsClosed(): void
    {
        $this->removePackageValue('algorithm');

        $this->expectInvalidAlgorithm();

        $this->lifetimeService();
    }

    /**
     * Rows of `[where, value]` for an algorithm that is set, in the guard's
     * overrides or the package config, but is not a string.
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideNonStringAlgorithms(): iterable
    {
        foreach (['guard override', 'package value'] as $where) {
            yield "{$where} as an integer" => [$where, 384];
            yield "{$where} as an array" => [$where, ['HS512']];
            yield "{$where} as a boolean" => [$where, true];
        }
    }

    /**
     * An algorithm override that is not a string fails closed instead of
     * falling back to the package algorithm, as does a package algorithm that
     * is not a string.
     *
     * @param  string  $where
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideNonStringAlgorithms')]
    public function testNonStringAlgorithmFailsClosed(string $where, mixed $value): void
    {
        if ($where === 'guard override') {
            $this->setGuardOverrides(['algorithm' => $value]);
        } else {
            config()->set('authentication.jwt.algorithm', $value);
        }

        $this->expectInvalidAlgorithm();

        $this->lifetimeService();
    }

    /**
     * A `null` algorithm override means "use the package algorithm".
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNullAlgorithmOverrideUsesThePackageAlgorithm(): void
    {
        config()->set('authentication.jwt.algorithm', 'HS384');
        config()->set('authentication.jwt.keys', [self::PACKAGE_KID => self::HS384_SECRET]);

        $this->setGuardOverrides(['algorithm' => null]);

        self::assertSame('HS384', $this->jwtHeader($this->issueAccessToken($this->lifetimeService()))['alg']);
    }

    /**
     * Rows of `[key, value]` for an issuer or audience that is set but neither
     * a string nor `null`.
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideNonStringClaimPolicies(): iterable
    {
        foreach (['issuer', 'audience'] as $key) {
            yield "{$key} as an array" => [$key, ['staff-api']];
            yield "{$key} as an integer" => [$key, 42];
            yield "{$key} as a boolean" => [$key, false];
        }
    }

    /**
     * An issuer or audience override that is neither a string nor `null` fails
     * closed: read as `null` it would turn the claim check off for the guard.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideNonStringClaimPolicies')]
    public function testNonStringClaimPolicyOverrideFailsClosed(string $key, mixed $value): void
    {
        $this->setGuardOverrides([$key => $value]);

        $this->expectInvalidClaimPolicy($key);

        $this->lifetimeService();
    }

    /**
     * A package issuer or audience that is neither a string nor `null` fails
     * closed for every guard that does not override it.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideNonStringClaimPolicies')]
    public function testNonStringClaimPolicyPackageValueFailsClosed(string $key, mixed $value): void
    {
        config()->set("authentication.jwt.{$key}", $value);

        $this->expectInvalidClaimPolicy($key);

        $this->lifetimeService();
    }

    /**
     * A `null` or empty audience override turns the audience check off for the
     * guard even when the package sets one, and a string override replaces it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAudienceOverrideReplacesOrTurnsOffThePackageAudience(): void
    {
        foreach ([null, ''] as $off) {

            $this->setGuardOverrides(['audience' => $off]);

            self::assertArrayNotHasKey(Claims::AUDIENCE->value, $this->issuedClaims($this->lifetimeService()));
        }

        $this->setGuardOverrides(['audience' => 'override-audience', 'issuer' => 'override-issuer']);

        $claims = $this->issuedClaims($this->lifetimeService());

        self::assertSame('override-audience', $claims[Claims::AUDIENCE->value]);
        self::assertSame('override-issuer', $claims[Claims::ISSUER->value]);
    }

    /**
     * A guard whose `jwt` entry is not an array fails closed rather than
     * silently losing its overrides.
     *
     * @return void
     */
    public function testNonArrayGuardJwtBlockFailsClosed(): void
    {
        config()->set('auth.guards.' . self::LIFETIME_GUARD . '.jwt', 'access_ttl_minutes=1');

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('Auth guard [package_default] `jwt` overrides must be an array.');

        $this->lifetimeService();
    }

    /**
     * A guard whose `jwt` entry is `null` has no overrides.
     *
     * @return void
     */
    public function testNullGuardJwtBlockMeansNoOverrides(): void
    {
        config()->set('auth.guards.' . self::LIFETIME_GUARD . '.jwt', null);

        self::assertSame(45, $this->lifetimeService()->lifetimes()->accessTtlMinutes);
    }

    /**
     * A guard's lifetimes for a principal type override the guard's own key by
     * key: each key a type sets wins (a digit string included), every other key
     * and the grace window stay the guard's, and a principal of a type the
     * guard does not list, or none, gets the guard's lifetimes.
     *
     * @return void
     */
    public function testPrincipalTypeLifetimesOverrideTheGuardKeyByKey(): void
    {
        $this->setGuardOverrides([
            'refresh_idle_ttl_minutes' => 9000,
            'by_principal_type'        => [
                'staff'   => ['access_ttl_minutes' => 2, 'refresh_absolute_ttl_minutes' => 600],
                'service' => ['refresh_idle_ttl_minutes' => '30', 'access_ttl_minutes' => null],
            ],
        ]);

        $service = $this->lifetimeService();
        $guard   = $service->lifetimes();
        $staff   = $service->lifetimesFor($this->principalOfType('staff'));
        $robot   = $service->lifetimesFor($this->principalOfType('service'));

        self::assertSame([2, 9000, 600, $guard->refreshGraceSeconds], $this->lifetimeValues($staff));
        self::assertSame([45, 30, $guard->refreshAbsoluteTtlMinutes, $guard->refreshGraceSeconds], $this->lifetimeValues($robot));
        self::assertSame($guard, $service->lifetimesFor($this->principalOfType('customer')));
        self::assertSame($guard, $service->lifetimesFor($this->principalOfType('')));
        self::assertSame($guard, $service->lifetimesFor(null));
    }

    /**
     * An access token for a principal of a type with its own access lifetime
     * expires after that lifetime, not the guard's.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokensExpireAfterTheirPrincipalTypesAccessLifetime(): void
    {
        $this->setGuardOverrides(['by_principal_type' => ['staff' => ['access_ttl_minutes' => 2]]]);

        $service  = $this->lifetimeService();
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('id-1');

        $staff = $this->principalOfType('staff');
        $staff->shouldReceive('getPrincipalIdentifier')->andReturn('pid-1');

        $other = $this->principalOfType('customer');
        $other->shouldReceive('getPrincipalIdentifier')->andReturn('pid-2');

        $staffClaims = $service->parse($service->issueAccessToken($identity, $staff, null), TokenType::ACCESS);
        $otherClaims = $service->parse($service->issueAccessToken($identity, $other, null), TokenType::ACCESS);

        self::assertIsArray($staffClaims);
        self::assertIsArray($otherClaims);
        self::assertSame(Carbon::now()->addMinutes(2)->getTimestamp(), $staffClaims[Claims::EXPIRES_AT->value]);
        self::assertSame(Carbon::now()->addMinutes(45)->getTimestamp(), $otherClaims[Claims::EXPIRES_AT->value]);
    }

    /**
     * Malformed `by_principal_type` maps, each with the message that names the
     * guard.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideMalformedPrincipalTypeMaps(): iterable
    {
        $keys = 'Auth guard [package_default] `jwt.by_principal_type.staff` may set only `access_ttl_minutes`,'
            . ' `refresh_idle_ttl_minutes`, `refresh_absolute_ttl_minutes`, not ';
        $map  = 'Auth guard [package_default] `jwt.by_principal_type` must be an array keyed by principal type.';
        $type = 'Auth guard [package_default] `jwt.by_principal_type` must map each principal type name to an array of lifetimes.';

        yield from [
            'a string'                  => ['staff', $map],
            'a list'                    => [[['access_ttl_minutes' => 2]], $type],
            'an empty type name'        => [['' => ['access_ttl_minutes' => 2]], $type],
            'lifetimes not an array'    => [['staff' => 2], $type],
            'lifetimes null'            => [['staff' => null], $type],
            'the grace window'          => [['staff' => ['refresh_grace_seconds' => 0]], $keys . '`refresh_grace_seconds`.'],
            'a misspelt and a list key' => [['staff' => ['access_ttl' => 2, 3]], $keys . '`access_ttl`, `0`.'],
        ];
    }

    /**
     * A malformed `by_principal_type` map fails closed when the guard's service
     * is resolved rather than being ignored.
     *
     * @param  mixed  $map
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedPrincipalTypeMaps')]
    public function testMalformedPrincipalTypeMapFailsClosed(mixed $map, string $message): void
    {
        $this->setGuardOverrides(['by_principal_type' => $map]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage($message);

        $this->lifetimeService();
    }

    /**
     * A `null` map means no lifetimes per type.
     *
     * @return void
     */
    public function testNullPrincipalTypeMapMeansNone(): void
    {
        $this->setGuardOverrides(['by_principal_type' => null]);

        $service = $this->lifetimeService();

        self::assertSame($service->lifetimes(), $service->lifetimesFor($this->principalOfType('staff')));
    }

    /**
     * A per-type lifetime that is not an integer fails closed, naming the
     * guard, the type and the key.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testMalformedPrincipalTypeLifetimeFailsClosed(mixed $value): void
    {
        $this->setGuardOverrides(['by_principal_type' => ['staff' => ['refresh_idle_ttl_minutes' => $value]]]);

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('Auth guard [package_default] `jwt.by_principal_type.staff.refresh_idle_ttl_minutes` must be an integer from 1 to 5256000.');

        $this->lifetimeService();
    }

    /**
     * Rows of `[key, value, maximum, accepted]` at and beyond each per-type
     * range bound.
     *
     * @return iterable<string, array{0: string, 1: int, 2: int, 3: bool}>
     */
    public static function providePrincipalTypeRangeBounds(): iterable
    {
        $ranges = [
            ['access_ttl_minutes', 1440],
            ['refresh_idle_ttl_minutes', 5256000],
            ['refresh_absolute_ttl_minutes', 5256000],
        ];

        foreach ($ranges as [$key, $max]) {
            yield "{$key} below the minimum" => [$key, 0, $max, false];
            yield "{$key} at the minimum" => [$key, 1, $max, true];
            yield "{$key} at the maximum" => [$key, $max, $max, true];
            yield "{$key} above the maximum" => [$key, $max + 1, $max, false];
        }
    }

    /**
     * Each per-type lifetime accepts exactly the range of the guard's.
     *
     * @param  string  $key
     * @param  int  $value
     * @param  int  $max
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('providePrincipalTypeRangeBounds')]
    public function testEachPrincipalTypeLifetimeAcceptsExactlyItsRange(string $key, int $value, int $max, bool $accepted): void
    {
        $this->setGuardOverrides(['by_principal_type' => ['staff' => [$key => $value]]]);

        if (!$accepted) {
            $this->expectException(InvalidJwtConfigurationException::class);
            $this->expectExceptionMessage("Auth guard [package_default] `jwt.by_principal_type.staff.{$key}` must be an integer from 1 to {$max}.");
        }

        $lifetimes = $this->lifetimeService()->lifetimesFor($this->principalOfType('staff'));
        $values    = array_combine(['access_ttl_minutes', 'refresh_idle_ttl_minutes', 'refresh_absolute_ttl_minutes', 'refresh_grace_seconds'], $this->lifetimeValues($lifetimes));

        self::assertSame($value, $values[$key]);
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
     * Build a standalone verifier for the named guard over the supplied key
     * map, using its first kid as the active kid.
     *
     * @param  string  $guard
     * @param  array<string, string>  $keys
     * @param  ?string  $audience
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function makeVerifier(string $guard, #[\SensitiveParameter] array $keys, ?string $audience = null): JwtTokenService
    {
        return new JwtTokenService(
            JwtKeyring::fromKeyMap($keys, (string) array_key_first($keys), 'HS256'),
            $guard,
            new TokenLifetimes(15, 60 * 24 * 30, 60 * 24 * 180, 30),
            30,
            null,
            $audience,
        );
    }

    /**
     * Resolve a fresh service for the guard.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lifetimeService(): JwtTokenService
    {
        $app = $this->app;

        assert($app !== null);

        return (new JwtTokenServiceFactory($app, $app->make(ConfigRepository::class)))->forGuard(self::LIFETIME_GUARD);
    }

    /**
     * The value the resolved service uses for the given key.
     *
     * @param  string  $key
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    private function resolved(string $key): int
    {
        $service   = $this->lifetimeService();
        $lifetimes = $service->lifetimes();

        return match ($key) {
            'access_ttl_minutes'           => $lifetimes->accessTtlMinutes,
            'refresh_idle_ttl_minutes'     => $lifetimes->refreshIdleTtlMinutes,
            'refresh_absolute_ttl_minutes' => $lifetimes->refreshAbsoluteTtlMinutes,
            'refresh_grace_seconds'        => $lifetimes->refreshGraceSeconds,
            default                        => $this->observedLeeway($service),
        };
    }

    /**
     * The clock-skew leeway a service applies, observed as the largest number
     * of seconds past its expiry at which an access token still parses.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $service
     * @return int
     *
     * @throws \Random\RandomException
     */
    private function observedLeeway(JwtTokenService $service): int
    {
        $token  = $this->issueAccessToken($service);
        $claims = $service->parse($token, TokenType::ACCESS);

        assert(is_array($claims) && is_int($claims['exp']));

        $leeway = -1;

        while ($leeway < 400) {

            JWT::$timestamp = $claims['exp'] + $leeway + 1;

            if ($service->parse($token, TokenType::ACCESS) === null) {
                break;
            }

            $leeway++;
        }

        JWT::$timestamp = Carbon::now()->getTimestamp();

        return $leeway + 1;
    }

    /**
     * Build a principal of the given type, acting within no tenant.
     *
     * @param  string  $type
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasType&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principalOfType(string $type): MockInterface
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasType&\SineMacula\Laravel\Authentication\Contracts\Principal $principal */
        $principal = \Mockery::mock(Principal::class, HasType::class);
        $principal->shouldReceive('getType')->andReturn($type);
        $principal->shouldReceive('getTenant')->andReturn(null);

        return $principal;
    }

    /**
     * The access, idle, absolute and grace values of the lifetimes, in order.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @return list<int>
     */
    private function lifetimeValues(TokenLifetimes $lifetimes): array
    {
        return [$lifetimes->accessTtlMinutes, $lifetimes->refreshIdleTtlMinutes, $lifetimes->refreshAbsoluteTtlMinutes, $lifetimes->refreshGraceSeconds];
    }

    /**
     * Set the guard's `jwt` overrides.
     *
     * @param  array<string, mixed>  $overrides
     * @return void
     */
    private function setGuardOverrides(array $overrides): void
    {
        config()->set('auth.guards.' . self::LIFETIME_GUARD . '.jwt', $overrides);
    }

    /**
     * Remove a key from the package `jwt` config entirely.
     *
     * @param  string  $key
     * @return void
     */
    private function removePackageValue(string $key): void
    {
        $jwt = config('authentication.jwt');

        assert(is_array($jwt));

        unset($jwt[$key]);

        config()->set('authentication.jwt', $jwt);
    }

    /**
     * Issue an access token with the service and return the claims the same
     * service verifies in it.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $service
     * @return array<string, mixed>
     *
     * @throws \Random\RandomException
     */
    private function issuedClaims(JwtTokenService $service): array
    {
        $claims = $service->parse($this->issueAccessToken($service), TokenType::ACCESS);

        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * Expect the factory to reject an algorithm that is missing or not a
     * string.
     *
     * @return void
     */
    private function expectInvalidAlgorithm(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(
            'JWT `algorithm` for guard [package_default] is missing or not a string:'
            . ' set `authentication.jwt.algorithm` or the guard\'s `jwt.algorithm` override.',
        );
    }

    /**
     * Expect the factory to reject an issuer or audience that is neither a
     * string nor `null`.
     *
     * @param  string  $key
     * @return void
     */
    private function expectInvalidClaimPolicy(string $key): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(
            "JWT `{$key}` for guard [package_default] must be a string or null:"
            . " set `authentication.jwt.{$key}` or the guard's `jwt.{$key}` override.",
        );
    }

    /**
     * Expect the factory to reject a key with its range in the message.
     *
     * @param  string  $key
     * @param  int  $min
     * @param  int  $max
     * @return void
     */
    private function expectInvalidKey(string $key, int $min, int $max): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(
            "JWT `{$key}` for guard [package_default] must be an integer from {$min} to {$max}:"
            . " set `authentication.jwt.{$key}` or the guard's `jwt.{$key}` override.",
        );
    }
}
