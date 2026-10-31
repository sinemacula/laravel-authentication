<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * End-to-end integration test for the package JwtGuard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string */
    private const string JWT_SECRET = 'integration-secret-with-at-least-32-bytes!';

    /** @var string Kid the signing secret is registered under. */
    private const string JWT_KID = 'test-kid';

    /** @var string */
    private const string AUTH_MIDDLEWARE = 'auth:api';

    /** @var string */
    private const string BEARER_PREFIX = 'Bearer ';

    /** @var \Carbon\Carbon */
    private Carbon $now;

    /**
     * Freeze the clock and create the in-memory identity table.
     *
     * @return void
     */
    #[\Override]
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
     * Release the frozen clock and drop the in-memory schema.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A valid JWT passes the `auth:api` middleware and exposes the identity via
     * `Auth::check()`, `Auth::id()`, and `Auth::user()`.
     *
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
     * A request with no Authorization header is rejected with 401.
     *
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
     * An expired JWT is rejected with 401.
     *
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
     * Rows of `[claim]`: time claims a correctly signed access token must
     * carry.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRequiredTimeClaims(): iterable
    {
        yield from [
            'no exp, so it never expires' => ['exp'],
            'no iat'                      => ['iat'],
        ];
    }

    /**
     * A correctly signed access token without a required time claim is rejected
     * with 401, so a token that never expires cannot authenticate.
     *
     * @param  string  $claim
     * @return void
     */
    #[DataProvider('provideRequiredTimeClaims')]
    public function testBearerTokenWithoutARequiredTimeClaimIsRejectedByAuthMiddleware(string $claim): void
    {
        $user = $this->seedUser();

        $claims = [
            'sub' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'pid' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'iat' => $this->now->getTimestamp(),
            'exp' => $this->now->getTimestamp() + 600,
        ];

        unset($claims[$claim]);

        Route::middleware(self::AUTH_MIDDLEWARE)->get('/me', static fn (): string => 'ok');

        $this->withHeaders(['Authorization' => self::BEARER_PREFIX . $this->encodeAccessToken($claims)])->getJson('/me')
            ->assertUnauthorized();
    }

    /**
     * An authenticated request exposes the resolved principal and device
     * through the `AuthManager` contextual accessors.
     *
     * @return void
     */
    public function testContextualAccessorsReturnResolvedValuesForAuthenticatedRequest(): void
    {
        $user = $this->seedUser();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $user->getMorphClass(),
            'principal_id'         => (string) $user->getKey(), // @phpstan-ignore cast.string
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

            /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
            $manager = app('auth');

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
     * A bearer token carrying a `did` still resolves the device from storage
     * and can therefore trigger the debounced `last_used_at` write on the
     * persisted device row.
     *
     * @return void
     */
    public function testBearerAuthWithDeviceRecordsItsLastUse(): void
    {
        $user = $this->seedUser();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $user->getMorphClass(),
            'principal_id'         => (string) $user->getKey(), // @phpstan-ignore cast.string
        ])->save();

        $token = $this->encodeAccessToken([
            'sub' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'pid' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'did' => $device->getKey(),
            'iat' => $this->now->getTimestamp(),
            'exp' => $this->now->getTimestamp() + 600,
        ]);

        Route::middleware(self::AUTH_MIDDLEWARE)->get('/last-used', static fn (): string => 'ok');

        $response = $this->withHeaders(['Authorization' => self::BEARER_PREFIX . $token])->get('/last-used');

        $response->assertOk();

        $fresh = Device::query()->findOrFail($device->getKey());

        assert($fresh instanceof Device);

        self::assertInstanceOf(Carbon::class, $fresh->last_used_at);
        self::assertTrue($this->now->equalTo($fresh->last_used_at));
    }

    /**
     * Revoking a device ends its session at once: an access token naming the
     * device is rejected exactly as if the device were missing, and its refresh
     * token no longer rotates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRevokingDeviceBlocksRefreshAndExistingAccessToken(): void
    {
        $user = $this->seedUser();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $user->getMorphClass(),
            'principal_id'         => (string) $user->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash('stored-rotation-id'),
        ])->save();

        $accessToken = $this->encodeAccessToken([
            'sub' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'pid' => (string) $user->getKey(), // @phpstan-ignore cast.string
            'did' => $device->getKey(),
            'iat' => $this->now->getTimestamp(),
            'exp' => $this->now->getTimestamp() + 600,
        ]);

        $manager      = $this->freshAuthManager();
        $refreshToken = $manager->jwt('api')->issueRefreshToken($device, 'stored-rotation-id');

        Device::query()
            ->whereKey($device->getKey())
            ->update(['revoked_at' => $this->now]);

        Route::middleware(self::AUTH_MIDDLEWARE)->get('/revoked-device', static fn (): string => 'ok');

        $response = $this->withHeaders([
            'Authorization' => self::BEARER_PREFIX . $accessToken,
        ])->getJson('/revoked-device');

        $response->assertStatus(401);

        $guard = $this->freshGuard();

        self::assertNull(GuardSessions::of($guard)->refresh($refreshToken)->session);
    }

    /**
     * Configure the JWT guard, provider, and in-memory sqlite.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
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

        $config->set('authentication.jwt.keys', [self::JWT_KID => self::JWT_SECRET]);
        $config->set('authentication.jwt.active_kid', self::JWT_KID);
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.access_ttl_minutes', 15);
    }

    /**
     * Persist and return a hashed-password identity row.
     *
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
     * Encode a signed access-token JWT from the supplied claims.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encodeAccessToken(array $claims): string
    {
        return JWT::encode(
            array_merge([Claims::JWT_ID->value => 'access-token-id'], $claims, [
                Claims::TYPE->value  => TokenType::ACCESS->value,
                Claims::GUARD->value => 'api',
            ]),
            self::JWT_SECRET,
            'HS256',
            self::JWT_KID,
        );
    }

    /**
     * Resolve a fresh package auth manager instance.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function freshAuthManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }

    /**
     * Resolve a fresh `api` JWT guard against the current request binding.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function freshGuard(): JwtGuard
    {
        app()->instance('request', Request::create('/refresh', 'POST'));

        $guard = $this->freshAuthManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
