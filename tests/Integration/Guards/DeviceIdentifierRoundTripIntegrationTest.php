<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\RenamedKeyDevice;
use Tests\Integration\Fixtures\RenamedKeyDeviceIdentity;
use Tests\TestCase;

/**
 * The device identifier a token carries is always the device's primary key, so
 * a device model whose key column is not `id` is found again by both the bearer
 * path and the refresh exchange, which look devices up by primary key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversTrait(ActsAsDevice::class)]
final class DeviceIdentifierRoundTripIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Plaintext rotation id stored on the seeded device. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /**
     * Create the identity and device tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        self::createDeviceTable('renamed_key_devices', 'device_uuid');
    }

    /**
     * Drop the identity and device tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('renamed_key_devices');
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * An access token names the device by its `device_uuid` key, and a request
     * carrying it through the `auth` middleware binds that device.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRequestBindsTheDeviceTheTokenNamesByPrimaryKey(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        $token = $this->tokens()->issueAccessToken($identity, $identity, $device);

        self::assertSame($device->getKey(), $this->tokens()->parse($token, TokenType::ACCESS)[Claims::DEVICE_ID->value] ?? null);

        Route::middleware('auth:api')->get('/device', static fn (): array => ['device' => Auth::device()?->getDeviceIdentifier()]);

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])
            ->getJson('/device')
            ->assertOk()
            ->assertExactJson(['device' => $device->getKey()]);
    }

    /**
     * A refresh token names the device by its `device_uuid` key, and the
     * exchange finds and rotates that device.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRotatesTheDeviceTheTokenNamesByPrimaryKey(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        $tokens = $this->guard()->refresh($this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity));

        self::assertNotNull($tokens);
        self::assertNotSame(RefreshTokenHasher::hash(self::ROTATION_ID), RenamedKeyDevice::query()->whereKey($device->getKey())->firstOrFail()->getRefreshKey());
    }

    /**
     * Configure the `api` guard and the device model.
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

        $config->set('authentication.device.model', RenamedKeyDevice::class);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => RenamedKeyDeviceIdentity::class,
        ]);
    }

    /**
     * Persist an identity with one live device holding the stored rotation.
     *
     * @return array{0: \Tests\Integration\Fixtures\RenamedKeyDeviceIdentity, 1: \Tests\Integration\Fixtures\RenamedKeyDevice}
     */
    private function seedIdentityWithDevice(): array
    {
        $identity = new RenamedKeyDeviceIdentity;
        $identity->forceFill(['email' => 'renamed-key@example.test', 'password' => 'irrelevant'])->save();

        $device = new RenamedKeyDevice;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => RenamedKeyDeviceIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return [$identity, $device];
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $tokens = Auth::jwt('api');

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * The `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(): JwtGuard
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $guard = $manager->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
