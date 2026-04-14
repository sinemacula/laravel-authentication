<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use Tests\Integration\Fixtures\AccessOnlyIdentity;

/**
 * Verifies the "access-only" usage pattern: the package works end-to-end with
 * no devices migration, no Device contract implementation, and no
 * refresh-token flow. Consumers who only need access tokens without device
 * binding or refresh can skip the devices table entirely, while the bearer path
 * still rehydrates the persisted identity through the configured provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(AuthServiceProvider::class)]
final class AccessOnlyIntegrationTest extends TestCase
{
    /** @var string Shared JWT secret used by the in-test guard. */
    private const string JWT_SECRET = 'access-only-secret-with-at-least-32-bytes!';

    /** @var string Guard name registered for the test. */
    private const string GUARD = 'api';

    /**
     * Provision only the identity table; deliberately do not create the devices
     * table or any other package-owned schema.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Issuing an access token with `null` device produces a JWT whose `did`
     * claim is explicitly null, so the bearer path sees no usable device hint
     * and still resolves identity + principal without needing a devices table.
     * The identity is still loaded through the configured provider.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testAccessTokenFlowSucceedsWithoutDevice(): void
    {
        $user = $this->seedUser();

        $jwtService = PackageAuth::jwt(self::GUARD);

        assert($jwtService !== null);

        $token  = $jwtService->issueAccessToken($user, $user, null);
        $claims = $jwtService->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertArrayHasKey(Claims::DEVICE_ID->value, $claims);
        self::assertNull($claims[Claims::DEVICE_ID->value] ?? null);
        self::assertFalse(Schema::hasTable('devices'));

        $request = Request::create('/me', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        app()->instance('request', $request);

        /** @var \SineMacula\Laravel\Authentication\Guards\JwtGuard $guard */
        $guard = app('auth')->guard(self::GUARD);

        self::assertTrue($guard->check(), 'Bearer verification must succeed without a device.');
        self::assertSame($user->getAuthIdentifier(), $guard->id());
        self::assertNotNull($guard->identity());
        self::assertNotNull($guard->principal());
        self::assertNull($guard->device());
        self::assertFalse(Schema::hasTable('devices'));
    }

    /**
     * A token that forges a non-null `did` against an access-only identity must
     * fail closed even though the deployment has no `devices` table.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgedDeviceHintFailsClosedWithoutDevicesTable(): void
    {
        $user = $this->seedUser();
        $now  = time();

        $token = JWT::encode([
            'sub' => (string) $user->getAuthIdentifier(), // @phpstan-ignore cast.string
            'pid' => (string) $user->getAuthIdentifier(), // @phpstan-ignore cast.string
            'did' => 'forged-device-id',
            'iat' => $now,
            'exp' => $now + 900,
            'typ' => TokenType::ACCESS->value,
        ], self::JWT_SECRET, 'HS256');

        self::assertFalse(Schema::hasTable('devices'));

        $request = Request::create('/me', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        app()->instance('request', $request);

        $guard = app('auth')->guard(self::GUARD);

        assert($guard instanceof JwtGuard);

        self::assertFalse(
            $guard->check(),
            'Bearer verification must fail closed when a token claims a device for an access-only identity.',
        );
        self::assertNull($guard->identity());
        self::assertNull($guard->principal());
        self::assertNull($guard->device());
        self::assertFalse(Schema::hasTable('devices'));
    }

    /**
     * Register the package service provider so the auth factory picks up the
     * `jwt` and `model` drivers.
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
     * Do not run the package's shipped devices migration; the test asserts the
     * package works without it.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        // intentionally empty
    }

    /**
     * Minimal Testbench environment: in-memory sqlite, a single `identities`
     * auth provider, and the `api` jwt guard.
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

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('auth.defaults.guard', self::GUARD);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => AccessOnlyIdentity::class,
        ]);

        $config->set('authentication.jwt.secret', self::JWT_SECRET);
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.access_ttl_minutes', 15);
    }

    /**
     * Seed a persisted access-only identity used as both the authenticated
     * subject and the acting principal in 2D mode.
     *
     * @return \Tests\Integration\Fixtures\AccessOnlyIdentity
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function seedUser(): AccessOnlyIdentity
    {
        $hasher = app(Hasher::class);

        $user           = new AccessOnlyIdentity;
        $user->email    = 'access-only@example.test';
        $user->password = $hasher->make('correct horse battery staple');
        $user->save();

        return $user;
    }
}
