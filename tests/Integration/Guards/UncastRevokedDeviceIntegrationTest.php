<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Integration\Fixtures\UncastDevice;
use Tests\Integration\Fixtures\UncastDeviceIdentity;
use Tests\TestCase;

/**
 * A revoked device is rejected on every path even when its model uses the
 * `ActsAsDevice` trait without a `datetime` cast on `revoked_at`, so the column
 * reads back as the raw string the database stores.
 *
 * Each test revokes the device the way the refresh exchange does, writing the
 * revocation time through the query builder and clearing the refresh digest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversTrait(ActsAsDevice::class)]
final class UncastRevokedDeviceIntegrationTest extends TestCase
{
    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Plaintext rotation id the device's refresh digest is built from. */
    private const string ROTATION_ID = 'plain-rotation-id';

    /**
     * Freeze the clocks and create the identity table.
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

        Schema::create('uncast_device_identities', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('uncast_device_identities');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * An access token naming the revoked device no longer authenticates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsTheRevokedDevice(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $device);

        self::assertTrue($this->guardForRequest($this->bearerRequest($token))->check());

        $this->revoke($device);

        self::assertFalse($this->guardForRequest($this->bearerRequest($token))->check());
    }

    /**
     * Pinning the revoked device on `attempt()` fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsTheRevokedDeviceWhenPinned(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        $this->revoke($device);

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'));

        self::assertFalse($guard->attempt(['email' => $identity->email, 'password' => self::PASSWORD], null, $device));
        self::assertFalse($guard->hasUser());
    }

    /**
     * Refreshing with the revoked device's refresh token fails with
     * `device_revoked`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsTheRevokedDeviceWithDeviceRevokedReason(): void
    {
        [, $device] = $this->seedIdentityWithDevice();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID);

        $this->revoke($device);

        Event::fake([RefreshFailed::class]);

        self::assertNull($this->guardForRequest(Request::create('/refresh', 'POST'))->refresh($refreshToken));

        Event::assertDispatched(
            RefreshFailed::class,
            static fn (RefreshFailed $event): bool => $event->reason === RefreshFailureReason::DEVICE_REVOKED,
        );
    }

    /**
     * Configure the JWT guard over the uncast device model.
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

        $config->set('authentication.device.model', UncastDevice::class);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => UncastDeviceIdentity::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity with one live device holding a refresh digest.
     *
     * @return array{0: \Tests\Integration\Fixtures\UncastDeviceIdentity, 1: \Tests\Integration\Fixtures\UncastDevice}
     */
    private function seedIdentityWithDevice(): array
    {
        $identity = new UncastDeviceIdentity;
        $identity->forceFill([
            'email'    => 'uncast@example.test',
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ])->save();

        $device = $identity->devices()->make();
        $device->forceFill(['os' => 'ios', 'refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)])->save();

        return [$identity, $device];
    }

    /**
     * Revoke the device as the refresh exchange does: set the revocation time
     * and clear the refresh digest through the query builder.
     *
     * @param  \Tests\Integration\Fixtures\UncastDevice  $device
     * @return void
     */
    private function revoke(UncastDevice $device): void
    {
        DB::table('devices')
            ->where('id', $device->getKey())
            ->update(['refresh_key' => null, 'revoked_at' => Carbon::now()]);
    }

    /**
     * Build a request carrying the bearer token.
     *
     * @param  string  $token
     * @return \Illuminate\Http\Request
     */
    private function bearerRequest(string $token): Request
    {
        return Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);
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
     * Resolve a fresh JWT guard bound to the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForRequest(Request $request): JwtGuard
    {
        app()->instance('request', $request);

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
