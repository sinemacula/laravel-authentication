<?php

declare(strict_types = 1);

namespace Tests\Integration\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use Tests\Concerns\InteractsWithJwtTokens;
use Tests\TestCase;

/**
 * Integration tests for the signing-key env convention in the shipped
 * `config/authentication.php`.
 *
 * Loads the shipped config file against controlled environment variables, so a
 * renamed env var or a changed default kid fails here rather than shipping
 * silently: `AUTHENTICATION_JWT_KEY` backs the `default` kid,
 * `AUTHENTICATION_JWT_ACTIVE_KID` defaults to `default`, and the issuer and
 * audience come from `AUTHENTICATION_JWT_ISSUER` and
 * `AUTHENTICATION_JWT_AUDIENCE` with no default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenServiceFactory::class)]
final class ShippedJwtKeyConfigTest extends TestCase
{
    use InteractsWithJwtTokens;

    /** @var string Env var backing the shipped `default` kid. */
    private const string KEY_ENV = 'AUTHENTICATION_JWT_KEY';

    /** @var string Env var selecting the active kid. */
    private const string ACTIVE_KID_ENV = 'AUTHENTICATION_JWT_ACTIVE_KID';

    /** @var string Signing key placed in the environment for the tests. */
    private const string KEY = 'shipped-config-test-key-with-at-least-32-bytes!';

    /** @var string Guard that resolves the package-wide JWT config. */
    private const string GUARD = 'shipped';

    /** @var string Issuer placed in the environment for the tests. */
    private const string ISSUER = 'https://auth.shipped.example.test';

    /** @var string Audience placed in the environment for the tests. */
    private const string AUDIENCE = 'https://api.shipped.example.test';

    /** @var list<string> Every env var the shipped `jwt` block reads. */
    private const array JWT_ENV = [
        self::KEY_ENV,
        self::ACTIVE_KID_ENV,
        'AUTHENTICATION_JWT_ALGORITHM',
        'AUTHENTICATION_JWT_ACCESS_TTL_MINUTES',
        'AUTHENTICATION_JWT_REFRESH_IDLE_TTL_MINUTES',
        'AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES',
        'AUTHENTICATION_JWT_REFRESH_GRACE_SECONDS',
        'AUTHENTICATION_JWT_LEEWAY_SECONDS',
        'AUTHENTICATION_JWT_ISSUER',
        'AUTHENTICATION_JWT_AUDIENCE',
    ];

    /** @var array<string, false|string> Ambient process-environment values of the JWT env vars, restored on teardown. */
    private array $ambientProcessEnvironment = [];

    /** @var array<array-key, mixed> Ambient `$_SERVER`, restored on teardown. */
    private array $ambientServer = [];

    /** @var array<array-key, mixed> Ambient `$_ENV`, restored on teardown. */
    private array $ambientEnv = [];

    /**
     * Save and clear every env var the shipped `jwt` block reads, so each test
     * starts from an unset environment whatever the shell or CI exports.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ambientServer = $_SERVER;
        $this->ambientEnv    = $_ENV;

        foreach (self::JWT_ENV as $name) {
            $this->ambientProcessEnvironment[$name] = getenv($name);
            $this->clearEnvironment($name);
        }

        config()->set('auth.guards.' . self::GUARD, [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
    }

    /**
     * Clear the values set by the test and restore the ambient environment so
     * nothing leaks into later tests.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->ambientProcessEnvironment as $name => $value) {
            putenv($value === false ? $name : "{$name}={$value}");
        }

        $_SERVER = $this->ambientServer;
        $_ENV    = $this->ambientEnv;

        parent::tearDown();
    }

    /**
     * The shipped key map holds one kid, `default`, read from
     * `AUTHENTICATION_JWT_KEY`, and the active kid defaults to `default`.
     *
     * @return void
     */
    public function testShippedKeyMapReadsDefaultKidFromEnv(): void
    {
        putenv(self::KEY_ENV . '=' . self::KEY);

        $jwt = $this->shippedJwtConfig();

        self::assertSame(['default' => self::KEY], $jwt['keys'] ?? null);
        self::assertSame('default', $jwt['active_kid'] ?? null);
    }

    /**
     * `AUTHENTICATION_JWT_ACTIVE_KID` selects the active kid in the shipped
     * config.
     *
     * @return void
     */
    public function testShippedActiveKidReadsFromEnv(): void
    {
        putenv(self::ACTIVE_KID_ENV . '=2026-05');

        self::assertSame('2026-05', $this->shippedJwtConfig()['active_kid'] ?? null);
    }

    /**
     * A JWT guard on the shipped config with `AUTHENTICATION_JWT_KEY` set signs
     * under the `default` kid and verifies its own tokens.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGuardSignsWithDefaultKidOnShippedConfig(): void
    {
        $this->putTokenSettings();

        config()->set('authentication.jwt', $this->shippedJwtConfig());

        $service = PackageAuth::jwt(self::GUARD);

        self::assertInstanceOf(JwtTokenService::class, $service);

        $token  = $this->issueAccessToken($service);
        $claims = $service->parse($token, TokenType::ACCESS);

        self::assertSame('default', $this->jwtHeader($token)['kid'] ?? null);
        self::assertNotNull($claims);
        self::assertSame(self::ISSUER, $claims[Claims::ISSUER->value]);
        self::assertSame(self::AUDIENCE, $claims[Claims::AUDIENCE->value]);
    }

    /**
     * The shipped config gives the issuer and the audience no default: with
     * neither variable set a guard on it fails closed, naming the issuer and
     * the variable to set, and with only the issuer set, the audience.
     *
     * @return void
     */
    public function testGuardRejectsShippedConfigWithoutIssuerOrAudience(): void
    {
        putenv(self::KEY_ENV . '=' . self::KEY);

        $jwt = $this->shippedJwtConfig();

        self::assertNull($jwt['issuer'] ?? null);
        self::assertNull($jwt['audience'] ?? null);

        $expectations = [
            'JWT `issuer` for guard [shipped] is required: set `authentication.jwt.issuer` (AUTHENTICATION_JWT_ISSUER) or the guard\'s `jwt.issuer` override.',
            'JWT `audience` for guard [shipped] is required: set `authentication.jwt.audience` (AUTHENTICATION_JWT_AUDIENCE) or the guard\'s `jwt.audience` override.',
        ];

        foreach ($expectations as $expected) {

            config()->set('authentication.jwt', $this->shippedJwtConfig());

            try {
                PackageAuth::jwt(self::GUARD);

                self::fail('Expected the guard to need an issuer and an audience.');
            } catch (InvalidJwtConfigurationException $exception) {
                self::assertSame($expected, $exception->getMessage());
            }

            putenv('AUTHENTICATION_JWT_ISSUER=' . self::ISSUER);
        }
    }

    /**
     * A JWT guard on the shipped config with `AUTHENTICATION_JWT_KEY` unset
     * fails closed with a message naming the `default` kid and pointing at the
     * env var.
     *
     * @return void
     */
    public function testGuardRejectsShippedConfigWithoutKeyEnv(): void
    {
        config()->set('authentication.jwt', $this->shippedJwtConfig());

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(
            'JWT key \'default\' in `authentication.jwt.keys` is not a string. Every kid must map to a non-empty'
            . ' string secret - check the env var backing this entry is set.',
        );

        PackageAuth::jwt(self::GUARD);
    }

    /**
     * Out of the box a guard issues 5-minute access tokens, keeps a session for
     * 90 days without a refresh and 180 days at most, gives a replaced refresh
     * token 30 seconds of grace, and allows 30 seconds of clock skew. The
     * shipped config is the only place those defaults live.
     *
     * @return void
     */
    public function testShippedLifetimesAreTheDocumentedDefaults(): void
    {
        $this->putTokenSettings();

        $jwt = $this->shippedJwtConfig();

        self::assertSame(5, $jwt['access_ttl_minutes'] ?? null);
        self::assertSame(60 * 24 * 90, $jwt['refresh_idle_ttl_minutes'] ?? null);
        self::assertSame(60 * 24 * 180, $jwt['refresh_absolute_ttl_minutes'] ?? null);
        self::assertSame(30, $jwt['leeway_seconds'] ?? null);

        config()->set('authentication.jwt', $jwt);

        $lifetimes = $this->shippedService()->lifetimes();

        self::assertSame(5, $lifetimes->accessTtlMinutes);
        self::assertSame(60 * 24 * 90, $lifetimes->refreshIdleTtlMinutes);
        self::assertSame(60 * 24 * 180, $lifetimes->refreshAbsoluteTtlMinutes);
        self::assertSame(30, $lifetimes->refreshGraceSeconds);
    }

    /**
     * The lifetimes read from the environment arrive as digit strings, which a
     * guard on the shipped config accepts as integers.
     *
     * @return void
     */
    public function testShippedLifetimesReadDigitStringsFromEnv(): void
    {
        $this->putTokenSettings();
        putenv('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES=10');
        putenv('AUTHENTICATION_JWT_REFRESH_IDLE_TTL_MINUTES=20160');
        putenv('AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES=43200');
        putenv('AUTHENTICATION_JWT_REFRESH_GRACE_SECONDS=45');

        $jwt = $this->shippedJwtConfig();

        self::assertSame('10', $jwt['access_ttl_minutes'] ?? null);

        config()->set('authentication.jwt', $jwt);

        $lifetimes = $this->shippedService()->lifetimes();

        self::assertSame(10, $lifetimes->accessTtlMinutes);
        self::assertSame(20160, $lifetimes->refreshIdleTtlMinutes);
        self::assertSame(43200, $lifetimes->refreshAbsoluteTtlMinutes);
        self::assertSame(45, $lifetimes->refreshGraceSeconds);
    }

    /**
     * `AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES=null` reads as an
     * explicit `null`, so a guard on the shipped config sets no absolute limit,
     * while its idle lifetime stays the default.
     *
     * @return void
     */
    public function testShippedAbsoluteLifetimeReadsNullFromEnv(): void
    {
        $this->putTokenSettings();
        putenv('AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES=null');

        $jwt = $this->shippedJwtConfig();

        self::assertArrayHasKey('refresh_absolute_ttl_minutes', $jwt);
        self::assertNull($jwt['refresh_absolute_ttl_minutes']);

        config()->set('authentication.jwt', $jwt);

        $lifetimes = $this->shippedService()->lifetimes();

        self::assertNull($lifetimes->refreshAbsoluteTtlMinutes);
        self::assertSame(60 * 24 * 90, $lifetimes->refreshIdleTtlMinutes);
    }

    /**
     * A lifetime in the environment that is not a whole number fails closed
     * when the guard is resolved, rather than being cast to some integer.
     *
     * @return void
     */
    public function testShippedLifetimeRejectsAMalformedEnvValue(): void
    {
        putenv(self::KEY_ENV . '=' . self::KEY);
        putenv('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES=5m');

        config()->set('authentication.jwt', $this->shippedJwtConfig());

        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT `access_ttl_minutes` for guard [shipped] must be an integer from 1 to 1440');

        PackageAuth::jwt(self::GUARD);
    }

    /**
     * Put the settings the shipped config needs from the environment for a
     * guard to resolve: the signing key, the issuer and the audience.
     *
     * @return void
     */
    private function putTokenSettings(): void
    {
        putenv(self::KEY_ENV . '=' . self::KEY);
        putenv('AUTHENTICATION_JWT_ISSUER=' . self::ISSUER);
        putenv('AUTHENTICATION_JWT_AUDIENCE=' . self::AUDIENCE);
    }

    /**
     * Resolve the guard's token service on the shipped config.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function shippedService(): JwtTokenService
    {
        $service = PackageAuth::jwt(self::GUARD);

        self::assertInstanceOf(JwtTokenService::class, $service);

        return $service;
    }

    /**
     * Load the shipped config file and return its `jwt` block.
     *
     * @return array<array-key, mixed>
     */
    private function shippedJwtConfig(): array
    {
        $config = require dirname(__DIR__, 3) . '/config/authentication.php';

        self::assertIsArray($config);
        self::assertIsArray($config['jwt'] ?? null);

        return $config['jwt'];
    }

    /**
     * Unset the named env var in every store Laravel's env repository reads:
     * `$_SERVER`, `$_ENV`, and the process environment.
     *
     * @param  string  $name
     * @return void
     */
    private function clearEnvironment(string $name): void
    {
        unset($_SERVER[$name], $_ENV[$name]);

        putenv($name);
    }
}
