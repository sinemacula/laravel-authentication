<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\DefaultUsersTableIdentity;
use Tests\TestCase;

/**
 * Proves that activation is opt-in end to end: a 2D user on a table shaped like
 * Laravel's default `users` table, with no `is_active` column and no
 * `CanBeActive` capability, signs in with credentials, authenticates bearer
 * requests, and refreshes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActivationPolicy::class)]
#[CoversClass(JwtGuard::class)]
final class ActivationOptInIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string */
    private const string ROTATION_ID = 'stored-rotation-id';

    /**
     * Create a table shaped like Laravel's default `users` table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('default_users', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('name');
            $blueprint->string('email')->unique();
            $blueprint->timestamp('email_verified_at')->nullable();
            $blueprint->string('password');
            $blueprint->rememberToken();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the default-users table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('default_users');

        parent::tearDown();
    }

    /**
     * A user with no activation column signs in with the correct password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUserWithoutActiveColumnSignsInWithCredentials(): void
    {
        $user = $this->seedUser();

        $guard = $this->freshGuard();

        self::assertTrue($guard->attempt(['email' => $user->email, 'password' => self::PASSWORD]));
        self::assertSame($user->getKey(), $guard->identity()?->getAuthIdentifier());
        self::assertSame($user->getKey(), $guard->principal()?->getPrincipalIdentifier());
    }

    /**
     * A user with no activation column authenticates a bearer request.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testUserWithoutActiveColumnAuthenticatesBearerRequest(): void
    {
        $user  = $this->seedUser();
        $token = $this->authManager()->jwt('api')->issueAccessToken($user, $user, null);

        Route::middleware('auth:api')->get('/me', static fn (): array => ['id' => Auth::id()]);

        $response = $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');

        $response->assertOk();
        $response->assertJson(['id' => $user->getKey()]);
    }

    /**
     * A user with no activation column refreshes a device-backed session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testUserWithoutActiveColumnRefreshes(): void
    {
        $user = $this->seedUser();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession('api', $user),
            'authenticatable_type' => DefaultUsersTableIdentity::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID, $user);

        $guard = $this->freshGuard();

        self::assertNotNull($guard->refresh($refreshToken));
        self::assertSame($user->getKey(), $guard->identity()?->getAuthIdentifier());
    }

    /**
     * Configure the JWT guard against the default-users provider.
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
            'provider' => 'default_users',
        ]);

        $config->set('auth.providers.default_users', [
            'driver' => 'model',
            'model'  => DefaultUsersTableIdentity::class,
        ]);
    }

    /**
     * Persist and return a user with a hashed password.
     *
     * @return \Tests\Integration\Fixtures\DefaultUsersTableIdentity
     */
    private function seedUser(): DefaultUsersTableIdentity
    {
        $user           = new DefaultUsersTableIdentity;
        $user->name     = 'Default User';
        $user->email    = 'default-user@example.test';
        $user->password = app(Hasher::class)->make(self::PASSWORD);
        $user->save();

        return $user->refresh();
    }

    /**
     * Resolve the package auth manager with no cached guards.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function authManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }

    /**
     * Resolve a fresh `api` JWT guard against a fresh request.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function freshGuard(): JwtGuard
    {
        app()->instance('request', Request::create('/sign-in', 'POST'));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
