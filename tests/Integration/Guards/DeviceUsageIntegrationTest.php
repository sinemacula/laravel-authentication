<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * End-to-end tests for recording a device's last use: bearer requests through
 * the `auth` middleware and refresh both record when, from which IP address,
 * and with which user agent the device was used, on the shipped table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDeviceUsage::class)]
#[CoversClass(ClientContext::class)]
final class DeviceUsageIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Plaintext rotation id stored on the seeded device. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /** @var string Timestamp format of the stored columns. */
    private const string DATETIME_FORMAT = 'Y-m-d H:i:s';

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /**
     * Freeze the clock, create the identity table, and register a route behind
     * the `auth` middleware that reports the bound device.
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

        Route::middleware('auth:api')->get('/device', static fn (): array => Auth::device() instanceof Device ? Auth::device()->toArray() : []);
    }

    /**
     * Release the frozen clocks and drop the identity table.
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
     * A bearer request records the time, the client's IP address, and its user
     * agent on the device it authenticates with.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRequestRecordsTheClientItCameFrom(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        $this->bearerRequest($identity, $device, '203.0.113.7', 'Client/1.0')->assertOk();

        self::assertSame(
            [$this->now->format(self::DATETIME_FORMAT), '203.0.113.7', 'Client/1.0'],
            $this->storedUsage($device),
        );
    }

    /**
     * Two requests served by the same application instance, as a long-running
     * worker serves them, each record their own client once the throttle window
     * has passed, and a request inside the window records nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachRequestRecordsItsOwnClientOutsideTheThrottleWindow(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        $this->bearerRequest($identity, $device, '203.0.113.7', 'Phone/1.0')->assertOk();

        $this->moveClockTo($this->now->copy()->addSeconds(30));

        $this->bearerRequest($identity, $device, '198.51.100.1', 'Inside/1.0')->assertOk();

        self::assertSame([$this->now->format(self::DATETIME_FORMAT), '203.0.113.7', 'Phone/1.0'], $this->storedUsage($device));

        $later = $this->now->copy()->addMinutes(2);

        $this->moveClockTo($later);

        $this->bearerRequest($identity, $device, '2001:db8::1', 'Laptop/2.0')->assertOk();

        self::assertSame([$later->format(self::DATETIME_FORMAT), '2001:db8::1', 'Laptop/2.0'], $this->storedUsage($device));
    }

    /**
     * A refresh records the client of the refresh request on the device it
     * rotated.
     *
     * @return void
     */
    public function testRefreshRecordsTheClientItCameFrom(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        Route::post('/refresh', function (): array {
            $tokens = $this->guard()->refresh(request()->string('refresh_token')->toString());

            return ['refreshed' => $tokens !== null];
        });

        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.10'])
            ->withHeaders(['User-Agent' => 'Refresher/3.1'])
            ->postJson('/refresh', ['refresh_token' => $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity)])
            ->assertOk()
            ->assertExactJson(['refreshed' => true]);

        self::assertSame([$this->now->format(self::DATETIME_FORMAT), '192.0.2.10', 'Refresher/3.1'], $this->storedUsage($device));
    }

    /**
     * A user agent with a NUL byte and invalid UTF-8 is stored cleaned instead
     * of failing the request, on every engine (PostgreSQL rejects both in a
     * text column).
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testCraftedUserAgentIsStoredCleaned(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        $this->bearerRequest($identity, $device, '203.0.113.7', "Crafted\0/1.0 \xC3\x28" . str_repeat('x', 600))->assertOk();

        $stored = $this->storedUsage($device)[2];

        self::assertIsString($stored);
        self::assertStringStartsWith('Crafted/1.0 ?(', $stored);
        self::assertSame(512, mb_strlen($stored, 'UTF-8'));
    }

    /**
     * The device a request binds serialises without either refresh digest.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBoundDeviceSerialisesWithoutItsDigests(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        DB::table('devices')->where('id', $device->getKey())->update(['previous_refresh_key' => RefreshTokenHasher::hash('older-rotation-id')]);

        $this->bearerRequest($identity, $device, '203.0.113.7', 'Client/1.0')
            ->assertOk()
            ->assertJsonPath('id', $device->getKey())
            ->assertJsonMissingPath('refresh_key')
            ->assertJsonMissingPath('previous_refresh_key');
    }

    /**
     * Configure the `api` guard over the identity table.
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

        $config->set('authentication.device.last_used_throttle_seconds', 60);
    }

    /**
     * Send a request to the device route with an access token for the device,
     * from the given client.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @param  string  $ip
     * @param  string  $userAgent
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Random\RandomException
     */
    private function bearerRequest(StubPrincipal $identity, Device $device, string $ip, string $userAgent): TestResponse
    {
        $token = $this->tokens()->issueAccessToken($identity, $identity, $device);

        return $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->withHeaders(['Authorization' => 'Bearer ' . $token, 'User-Agent' => $userAgent])
            ->getJson('/device');
    }

    /**
     * Move the application and JWT clocks to the given time.
     *
     * @param  \Carbon\Carbon  $at
     * @return void
     */
    private function moveClockTo(Carbon $at): void
    {
        Carbon::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }

    /**
     * Persist an identity with one live device holding the stored rotation.
     *
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Device}
     */
    private function seedIdentityWithDevice(): array
    {
        $identity            = new StubPrincipal;
        $identity->email     = 'device-usage@example.test';
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return [$identity, $device];
    }

    /**
     * Read the stored last-use time, IP address, and user agent of a device.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return list<mixed>
     */
    private function storedUsage(Device $device): array
    {
        $row = DB::table('devices')->where('id', $device->getKey())->first(['last_used_at', 'last_used_ip', 'last_used_user_agent']);

        self::assertNotNull($row);

        $lastUsedAt = $row->last_used_at === null ? null : Carbon::parse($row->last_used_at)->format(self::DATETIME_FORMAT); // @phpstan-ignore argument.type

        return [$lastUsedAt, $row->last_used_ip, $row->last_used_user_agent];
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
