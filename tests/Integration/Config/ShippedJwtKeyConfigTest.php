<?php

declare(strict_types = 1);

namespace Tests\Integration\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
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
 * silently: `AUTHENTICATION_JWT_KEY` backs the `default` kid, and
 * `AUTHENTICATION_JWT_ACTIVE_KID` defaults to `default`.
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

    /** @var list<string> Every env var the shipped `jwt` block reads. */
    private const array JWT_ENV = [
        self::KEY_ENV,
        self::ACTIVE_KID_ENV,
        'AUTHENTICATION_JWT_ALGORITHM',
        'AUTHENTICATION_JWT_ACCESS_TTL_MINUTES',
        'AUTHENTICATION_JWT_REFRESH_TTL_MINUTES',
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
        putenv(self::KEY_ENV . '=' . self::KEY);

        config()->set('authentication.jwt', $this->shippedJwtConfig());

        $service = PackageAuth::jwt(self::GUARD);

        self::assertInstanceOf(JwtTokenService::class, $service);

        $token = $this->issueAccessToken($service);

        self::assertSame('default', $this->jwtHeader($token)['kid'] ?? null);
        self::assertNotNull($service->parse($token, TokenType::ACCESS));
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
