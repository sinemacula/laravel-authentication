<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Jwt\Claims;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * End-to-end integration test for the package JwtGuard.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class JwtGuardIntegrationTest extends TestCase
{
    /** @var string */
    private const string JWT_SECRET = 'integration-secret-with-at-least-32-bytes!';

    /** @var string */
    private const string AUTH_MIDDLEWARE = 'auth:api';

    /** @var string */
    private const string BEARER_PREFIX = 'Bearer ';

    /** @var \Carbon\Carbon */
    private Carbon $now;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testValidBearerTokenPassesAuthMiddlewareAndResolvesIdentity(): void
    {
        $user = $this->seedUser();

        $token = $this->encodeAccessToken([
            'sub' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'pid' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'iat' => $this->now->getTimestamp(),
            'exp' => $this->now->getTimestamp() + 600,
        ]);

        Route::middleware(self::AUTH_MIDDLEWARE)->get('/me', static fn (): array => [
            'check'    => Auth::check(),
            'id'       => Auth::id(),
            'user_key' => Auth::user()?->getAuthIdentifier(),
        ]);

        $response = $this->withHeaders(['Authorization' => self::BEARER_PREFIX . $token])->getJson('/me');

        $response->assertOk();
        $response->assertJson([
            'check'    => true,
            'id'       => (string) $user->getKey(), // @phpstan-ignore cast.string
            'user_key' => (string) $user->getKey(), // @phpstan-ignore cast.string
        ]);
    }

    /**
     * @return void
     */
    public function testRequestWithoutBearerTokenIsRejectedByAuthMiddleware(): void
    {
        $this->seedUser();

        Route::middleware(self::AUTH_MIDDLEWARE)->get('/me', static fn (): string => 'ok');

        $response = $this->getJson('/me');

        $response->assertStatus(401);
    }

    /**
     * @return void
     */
    public function testExpiredBearerTokenIsRejectedByAuthMiddleware(): void
    {
        $user = $this->seedUser();

        $token = $this->encodeAccessToken([
            'sub' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'pid' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'iat' => $this->now->getTimestamp() - 3600,
            'exp' => $this->now->getTimestamp() - 60,
        ]);

        Route::middleware(self::AUTH_MIDDLEWARE)->get('/me', static fn (): string => 'ok');

        $response = $this->withHeaders(['Authorization' => self::BEARER_PREFIX . $token])->getJson('/me');

        $response->assertStatus(401);
    }

    /**
     * @return void
     */
    public function testContextualAccessorsReturnResolvedValuesForAuthenticatedRequest(): void
    {
        $user = $this->seedUser();

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash('stored-rotation-id'),
        ])->save();

        $token = $this->encodeAccessToken([
            'sub' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'pid' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'did' => $device->getKey(),
            'iat' => $this->now->getTimestamp(),
            'exp' => $this->now->getTimestamp() + 600,
        ]);

        Route::middleware(self::AUTH_MIDDLEWARE)->get('/context', static function (): array {
            $manager = app('auth');

            assert($manager instanceof \SineMacula\Laravel\Authentication\AuthManager);

            return [
                'principal_present' => $manager->principal() !== null,
                'device_present'    => $manager->device()    !== null,
                'device_key'        => $manager->device()?->getDeviceIdentifier(),
            ];
        });

        $response = $this->withHeaders(['Authorization' => self::BEARER_PREFIX . $token])->getJson('/context');

        $response->assertOk();
        $response->assertJson([
            'principal_present' => true,
            'device_present'    => true,
            'device_key'        => $device->getKey(),
        ]);
    }

    /**
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('auth.defaults.guard', 'api');

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('laravel-authentication.jwt.secret', self::JWT_SECRET);
        $config->set('laravel-authentication.jwt.algorithm', 'HS256');
        $config->set('laravel-authentication.jwt.access_ttl_minutes', 15);
    }

    /**
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedUser(): StubPrincipal
    {
        $hasher = app(Hasher::class);

        $user           = new StubPrincipal;
        $user->email    = 'jwt-integration@example.test';
        $user->password = $hasher->make('correct horse battery staple');
        $user->save();

        return $user;
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encodeAccessToken(array $claims): string
    {
        return JWT::encode(
            array_merge($claims, [Claims::TYPE => Claims::TYPE_ACCESS]),
            self::JWT_SECRET,
            'HS256',
        );
    }
}
