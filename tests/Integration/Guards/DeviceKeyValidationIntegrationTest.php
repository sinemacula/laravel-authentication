<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Devices\DeviceKeyShape;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Concerns\InteractsWithDevices;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\PrefixedKeyDevice;
use Tests\Integration\Fixtures\PrefixedKeyDeviceIdentity;
use Tests\TestCase;

/**
 * A device model that implements `ValidatesDeviceKey` decides which `did`
 * values the bearer and refresh paths look up: a stored device whose key the
 * model rejects is treated as unknown, although a plain string key would
 * otherwise be looked up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceKeyShape::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversTrait(VerifiesPinnedContext::class)]
final class DeviceKeyValidationIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Plaintext rotation id stored on the seeded devices. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /** @var string Key in the shape the device model accepts. */
    private const string VALID_KEY = 'dev_a1b2c3d4';

    /** @var string Stored key in a shape the device model rejects. */
    private const string LEGACY_KEY = 'legacy-device-1';

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

        Schema::create('prefixed_key_devices', static function (Blueprint $blueprint): void {
            $blueprint->string('id')->primary();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();
            $blueprint->dateTime('principal_switched_at', 0)->nullable();
            $blueprint->string('guard')->nullable();
            $blueprint->string('sign_in_method')->nullable();
            $blueprint->string('refresh_key', 64)->nullable();
            $blueprint->string('previous_refresh_key', 64)->nullable();
            $blueprint->dateTime('refresh_rotated_at', 0)->nullable();
            $blueprint->dateTime('signed_in_at', 0);
            $blueprint->dateTime('idle_expires_at', 0);
            $blueprint->dateTime('absolute_expires_at', 0);
            $blueprint->dateTime('revoked_at', 0)->nullable();
            $blueprint->string('revoked_reason', 64)->nullable();
            $blueprint->dateTime('last_used_at', 0)->nullable();
            $blueprint->string('last_used_ip', 45)->nullable();
            $blueprint->string('last_used_user_agent', 512)->nullable();
            $blueprint->datetimes(0);
        });
    }

    /**
     * Drop the identity and device tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('prefixed_key_devices');
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * A bearer token naming a stored device by a key the model accepts binds
     * the device; one naming a stored device by a key the model rejects is
     * refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerLooksUpOnlyDeviceKeysTheModelAccepts(): void
    {
        $identity = $this->seedIdentity();
        $valid    = $this->seedDevice($identity, self::VALID_KEY);
        $legacy   = $this->seedDevice($identity, self::LEGACY_KEY);

        $guard = $this->bearerGuard($this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $valid));

        self::assertTrue($identity->is($guard->user()));
        self::assertSame(self::VALID_KEY, $guard->device()?->getDeviceIdentifier());

        self::assertNull($this->bearerGuard($this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $legacy))->user());
    }

    /**
     * A refresh token naming a stored device by a key the model accepts
     * rotates; one naming a stored device by a key the model rejects fails as
     * `device_unknown` and leaves that device's rotation untouched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshLooksUpOnlyDeviceKeysTheModelAccepts(): void
    {
        $identity = $this->seedIdentity();
        $valid    = $this->seedDevice($identity, self::VALID_KEY);
        $legacy   = $this->seedDevice($identity, self::LEGACY_KEY);

        $reasons = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNotNull(GuardSessions::of($this->refreshGuard())->refresh($this->authManager()->jwt('api')->issueRefreshToken($valid, self::ROTATION_ID, $identity))->session);
        self::assertNull(GuardSessions::of($this->refreshGuard())->refresh($this->authManager()->jwt('api')->issueRefreshToken($legacy, self::ROTATION_ID, $identity))->session);
        self::assertSame([FailureReason::DEVICE_UNKNOWN], $reasons);

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), PrefixedKeyDevice::query()->findOrFail(self::LEGACY_KEY)->getRefreshKey());
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

        $config->set('authentication.device.model', PrefixedKeyDevice::class);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => PrefixedKeyDeviceIdentity::class,
        ]);
    }

    /**
     * Persist an identity.
     *
     * @return \Tests\Integration\Fixtures\PrefixedKeyDeviceIdentity
     */
    private function seedIdentity(): PrefixedKeyDeviceIdentity
    {
        $identity = new PrefixedKeyDeviceIdentity;
        $identity->forceFill(['email' => 'prefixed@example.test', 'password' => 'irrelevant'])->save();

        return $identity;
    }

    /**
     * Persist a device for the identity under the given key, holding the stored
     * rotation.
     *
     * @param  \Tests\Integration\Fixtures\PrefixedKeyDeviceIdentity  $identity
     * @param  string  $key
     * @return \Tests\Integration\Fixtures\PrefixedKeyDevice
     */
    private function seedDevice(PrefixedKeyDeviceIdentity $identity, string $key): PrefixedKeyDevice
    {
        $device = new PrefixedKeyDevice;
        $device->forceFill([
            ...self::liveSession(),
            'id'                   => $key,
            'authenticatable_type' => PrefixedKeyDeviceIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return $device;
    }

    /**
     * Resolve a fresh `api` guard for a request carrying the bearer token.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearerGuard(#[\SensitiveParameter] string $token): JwtGuard
    {
        return $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));
    }

    /**
     * Resolve a fresh `api` guard for a refresh request.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function refreshGuard(): JwtGuard
    {
        return $this->guardForRequest(Request::create('/refresh', 'POST'));
    }

    /**
     * Resolve a fresh `api` guard bound to the request.
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
}
