<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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
     * A request that sends no `User-Agent` header, once the throttle window has
     * passed, records its IP address and no user agent in place of the one an
     * earlier request recorded: the stored client is the client of that use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRequestWithoutAUserAgentRecordsNoneInPlaceOfTheEarlierOne(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();

        $this->bearerRequest($identity, $device, '203.0.113.7', 'Phone/1.0')->assertOk();

        $later = $this->now->copy()->addMinutes(2);

        $this->moveClockTo($later);

        $request = Request::create('/device', 'GET', server: [
            'REMOTE_ADDR'        => '198.51.100.1',
            'HTTP_AUTHORIZATION' => 'Bearer ' . $this->tokens()->issueAccessToken($identity, $identity, $device),
        ]);

        $request->server->remove('HTTP_USER_AGENT');
        $request->headers->remove('User-Agent');

        self::assertSame(200, app(HttpKernel::class)->handle($request)->getStatusCode());
        self::assertSame([$later->format(self::DATETIME_FORMAT), '198.51.100.1', null], $this->storedUsage($device));
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
     * A bearer request and a refresh record their client on the device they
     * used and on no other: another device of the same identity and a device of
     * another identity keep their own last use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRecordsTheClientOnlyOnTheDeviceThatWasUsed(): void
    {
        [$identity, $device] = $this->seedIdentityWithDevice();
        [$stranger]          = $this->seedIdentityWithDevice('stranger@example.test');

        $earlier = $this->now->copy()->subDay();
        $others  = [
            $this->seedDevice($identity, ['last_used_at' => $earlier, 'last_used_ip' => '198.51.100.9', 'last_used_user_agent' => 'Sibling/1.0']),
            $this->seedDevice($stranger, ['last_used_at' => $earlier, 'last_used_ip' => '198.51.100.10', 'last_used_user_agent' => 'Stranger/1.0']),
        ];

        $before = array_map($this->storedUsage(...), $others);

        Route::post('/refresh', fn (): array => ['refreshed' => $this->guard()->refresh(request()->string('refresh_token')->toString()) !== null]);

        $this->bearerRequest($identity, $device, '203.0.113.7', 'Client/1.0')->assertOk();

        self::assertSame([$this->now->format(self::DATETIME_FORMAT), '203.0.113.7', 'Client/1.0'], $this->storedUsage($device));
        self::assertSame($before, array_map($this->storedUsage(...), $others));

        $this->moveClockTo($this->now->copy()->addMinutes(2));

        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.10'])
            ->withHeaders(['User-Agent' => 'Refresher/3.1'])
            ->postJson('/refresh', ['refresh_token' => $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity)])
            ->assertExactJson(['refreshed' => true]);

        self::assertSame('192.0.2.10', $this->storedUsage($device)[1]);
        self::assertSame($before, array_map($this->storedUsage(...), $others));
    }

    /**
     * A device created as the README shows records the guard, the principal,
     * and the client it was created from, with the client's IP address and user
     * agent cleaned by `ClientContext` so a crafted header is stored rather
     * than failing the insert, and the tokens issued for it then work on the
     * bearer path and on refresh.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testDeviceCreatedAsDocumentedRecordsWhereItWasCreated(): void
    {
        [$identity] = $this->seedIdentityWithDevice();

        $this->routeDocumentedSignIn($identity);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '2001:db8::7'])
            ->withHeaders(['User-Agent' => "Crafted\0/1.0 \xC3\x28" . str_repeat('x', 600)])
            ->postJson('/sign-in', ['client_name' => 'Work laptop', 'platform' => 'macOS'])
            ->assertOk();

        $row = (array) DB::table('devices')->where('id', $response->json('device'))->first();

        self::assertSame('api', $row['guard']);
        self::assertSame(StubPrincipal::class, $row['principal_type']);
        self::assertSame((string) $identity->getKey(), $row['principal_id']); // @phpstan-ignore cast.string
        self::assertSame(['Work laptop', 'macOS', '2001:db8::7'], [$row['client_name'], $row['platform'], $row['created_ip']]);
        self::assertIsString($row['created_user_agent']);
        self::assertStringStartsWith('Crafted/1.0 ?(', $row['created_user_agent']);
        self::assertSame(512, mb_strlen($row['created_user_agent'], 'UTF-8'));

        $access  = $response->json('access_token');
        $refresh = $response->json('refresh_token');

        self::assertIsString($access);
        self::assertIsString($refresh);

        $this->withHeaders(['Authorization' => 'Bearer ' . $access])->getJson('/device')->assertOk()->assertJsonPath('id', $response->json('device'));

        self::assertNotNull($this->guard()->refresh($refresh));
    }

    /**
     * Rows of `[sign-in input]`: client names and platforms the documented
     * validation rejects, each of which would otherwise fail the request or be
     * stored cut short on some engine.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideUnsafeClientMetadata(): iterable
    {
        yield from [
            'name with a NUL byte'          => [['client_name' => "Work\0laptop"]],
            'platform with invalid UTF-8'   => [['platform' => "mac\xFFOS"]],
            'name over 255 characters'      => [['client_name' => str_repeat('é', 256)]],
            'platform that is not a string' => [['platform' => ['macOS']]],
        ];
    }

    /**
     * The README's sign-in validates the client name and platform before
     * storing them, so a client sending one that cannot be stored gets a
     * validation error instead of a server error, and no device is created.
     *
     * @param  array<string, mixed>  $input
     * @return void
     */
    #[DataProvider('provideUnsafeClientMetadata')]
    public function testDeviceCreatedAsDocumentedRejectsClientMetadataThatCannotBeStored(array $input): void
    {
        [$identity] = $this->seedIdentityWithDevice();

        $this->routeDocumentedSignIn($identity);

        $this->post('/sign-in', $input, ['Accept' => 'application/json'])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(array_keys($input));

        self::assertSame(1, DB::table('devices')->count());
    }

    /**
     * A client name and platform of exactly 255 characters, multibyte ones
     * included, pass the documented validation and are stored whole on every
     * engine.
     *
     * @return void
     */
    public function testDeviceCreatedAsDocumentedStoresClientMetadataUpTo255Characters(): void
    {
        [$identity] = $this->seedIdentityWithDevice();

        $this->routeDocumentedSignIn($identity);

        $name     = str_repeat('é', 255);
        $platform = str_repeat('日', 255);
        $device   = $this->postJson('/sign-in', ['client_name' => $name, 'platform' => $platform])->assertOk()->json('device');

        self::assertSame([$name, $platform], array_values((array) DB::table('devices')->where('id', $device)->first(['client_name', 'platform'])));
    }

    /**
     * A user agent with a NUL byte and invalid UTF-8 is stored cleaned on every
     * engine, instead of failing the request (invalid UTF-8) or being cut short
     * at the NUL byte (PostgreSQL).
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
     * Register a `/sign-in` route that creates a device for the identity and
     * issues its tokens exactly as the README shows.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @return void
     */
    private function routeDocumentedSignIn(StubPrincipal $identity): void
    {
        Route::post('/sign-in', function () use ($identity): array {
            $tokens    = $this->tokens();
            $lifetimes = $tokens->lifetimes();
            $absolute  = $lifetimes->absoluteDeadline(Carbon::now());
            $rotation  = RefreshTokenHasher::generate();
            $client    = ClientContext::fromRequest(request());
            $described = request()->validate([ // @phpstan-ignore staticMethod.dynamicCall
                'client_name' => ['nullable', 'string', 'max:255', 'regex:/^[^\x00]*$/u'],
                'platform'    => ['nullable', 'string', 'max:255', 'regex:/^[^\x00]*$/u'],
            ]);

            $device = new Device($described);
            $device->forceFill([
                'authenticatable_type' => $identity->getMorphClass(),
                'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
                'principal_type'       => $identity->getMorphClass(),
                'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
                'guard'                => 'api',
                'sign_in_method'       => 'password',
                'created_ip'           => $client->ip,
                'created_user_agent'   => $client->userAgent,
                'refresh_key'          => RefreshTokenHasher::hash($rotation),
                'idle_expires_at'      => $lifetimes->idleDeadline(Carbon::now(), $absolute),
                'absolute_expires_at'  => $absolute,
            ])->save();

            return [
                'device'        => $device->getKey(),
                'access_token'  => $tokens->issueAccessToken($identity, $identity, $device),
                'refresh_token' => $tokens->issueRefreshToken($device, $rotation, $identity),
            ];
        });
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
     * @param  string  $email
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Device}
     */
    private function seedIdentityWithDevice(string $email = 'device-usage@example.test'): array
    {
        $identity            = new StubPrincipal;
        $identity->email     = $email;
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        return [$identity, $this->seedDevice($identity, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)])];
    }

    /**
     * Persist a live device of the identity with any further state.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  array<string, mixed>  $state
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(StubPrincipal $identity, array $state): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            ...$state,
        ])->save();

        return $device;
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
