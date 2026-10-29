<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\RelationDevicesIdentity;
use Tests\TestCase;

/**
 * Bearer `did` resolution through a real `morphMany` devices relation.
 *
 * The guard routes the relation to the write connection, checks the `did`
 * against the relation's device model, and loads the device through it, so this
 * covers the relation (rather than plain builder) form of each step.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardDeviceRelationIntegrationTest extends TestCase
{
    use InteractsWithDevices;

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

        Schema::create('relation_devices_identities', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
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
        Schema::dropIfExists('relation_devices_identities');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A `did` naming one of the identity's devices binds that device.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerBindsADeviceLoadedThroughTheRelation(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);

        $guard = $this->guardForBearer($this->accessToken($identity, $device));

        self::assertTrue($guard->check());
        self::assertSame($device->getKey(), $guard->device()?->getDeviceIdentifier());
    }

    /**
     * A device revoked after the token was issued is rejected like a missing
     * one.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsARevokedDeviceLoadedThroughTheRelation(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);
        $token    = $this->accessToken($identity, $device);

        Device::query()->whereKey($device->getKey())->update(['revoked_at' => Carbon::now()]);

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * A `did` that cannot be a key of the relation's device model is rejected
     * without querying the devices table.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsAMalformedDidWithoutQueryingTheRelation(): void
    {
        $identity = $this->seedIdentity();

        $malformed = new Device;
        $malformed->forceFill([...self::liveSession(), 'id' => 'not-a-uuid']);

        $token = $this->accessToken($identity, $malformed);

        DB::enableQueryLog();

        self::assertFalse($this->guardForBearer($token)->check());

        $deviceQueries = array_filter(
            DB::getQueryLog(),
            static fn (array $entry): bool => preg_match('/[`"]devices[`"]/', $entry['query']) === 1,
        );

        self::assertSame([], $deviceQueries);
    }

    /**
     * Configure the `api` guard over the relation-backed identity.
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

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => RelationDevicesIdentity::class]);
    }

    /**
     * Persist an identity.
     *
     * @return \Tests\Integration\Fixtures\RelationDevicesIdentity
     */
    private function seedIdentity(): RelationDevicesIdentity
    {
        $identity = new RelationDevicesIdentity;
        $identity->forceFill([
            'email'    => 'relation@example.test',
            'password' => 'hashed',
        ])->save();

        return $identity;
    }

    /**
     * Persist a device owned by the identity through the relation.
     *
     * @param  \Tests\Integration\Fixtures\RelationDevicesIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(RelationDevicesIdentity $identity): Device
    {
        $device = $identity->devices()->make();
        $device->forceFill(self::liveSession(principal: $identity))->save();

        return $device;
    }

    /**
     * Issue an access token for the identity and device through the guard's
     * token service.
     *
     * @param  \Tests\Integration\Fixtures\RelationDevicesIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function accessToken(RelationDevicesIdentity $identity, Device $device): string
    {
        return $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $device);
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
     * Resolve a fresh `api` guard for a request carrying the bearer token.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForBearer(string $token): JwtGuard
    {
        app()->instance('request', Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
