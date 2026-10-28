<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\Integration\Fixtures\SeparateConnectionDeviceIdentity;
use Tests\TestCase;

/**
 * End-to-end tests for a device model kept on its own connection, apart from
 * the identities: refresh and the bearer path read and write the device on that
 * connection, and a replay revocation is reported once it is committed there,
 * whatever a transaction on another connection does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceRevoked::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(RefreshRotationStore::class)]
final class SeparateDeviceConnectionIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Plaintext rotation id of the device's first refresh token. */
    private const string ROTATION_ID = 'first-rotation-id';

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /** @var \ArrayObject<int, string> Names of the refresh outcome events, in dispatch order. */
    private \ArrayObject $dispatched;

    /**
     * Freeze the clocks, create the identity table on the default connection
     * and the device table on the device's own, record the refresh outcome
     * events, and register a route behind the `auth` middleware.
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

        self::createDeviceTable('devices', 'id', SeparateConnectionDevice::CONNECTION);

        $this->dispatched = new \ArrayObject;

        $dispatched = $this->dispatched;

        Event::listen([DeviceRevoked::class, AuthenticationFailed::class, Failed::class, Refreshed::class], static function (object $event) use ($dispatched): void {
            $dispatched->append(class_basename($event));
        });

        Route::middleware('auth:api')->get('/me', static fn (): array => ['device' => Auth::device()?->getDeviceIdentifier()]);
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
     * A refresh rotates the device on its own connection, the new access token
     * authenticates through the `auth` middleware, and nothing is written to
     * the default connection's devices table.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshAndBearerUseTheDevicesOwnConnection(): void
    {
        [$identity, $device] = $this->signIn();

        $pair = $this->guard()->refresh($this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity));

        self::assertNotNull($pair);
        self::assertSame(RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)), $this->row($device)['refresh_key']);
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->row($device)['previous_refresh_key']);

        $this->withHeaders(['Authorization' => 'Bearer ' . $pair->accessToken])->getJson('/me')->assertOk()->assertJson(['device' => $device->id]);

        self::assertSame(0, DB::table('devices')->count());
    }

    /**
     * A replay revokes the device on its own connection, which commits at once,
     * so `DeviceRevoked` is dispatched at once, before `Failed` and
     * `AuthenticationFailed`, even inside a transaction on the default
     * connection; that transaction rolling back neither undoes the revocation
     * nor withdraws the event.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testReplayIsReportedAtOnceWhateverAnotherConnectionsTransactionDoes(): void
    {
        $replay = $this->replayableToken();

        DB::beginTransaction();

        self::assertNull($this->guard()->refresh($replay));
        self::assertSame(['DeviceRevoked', 'Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());

        DB::rollBack();

        self::assertSame(['DeviceRevoked', 'Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());
        self::assertSame('rotation_reuse', $this->row($this->device())['revoked_reason']);
    }

    /**
     * Inside a transaction on the device's own connection the revocation is
     * reported only when that transaction commits, after `Failed` and
     * `AuthenticationFailed`, and never when it is rolled back, which also
     * leaves the device live.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testReplayInsideTheDeviceConnectionsTransactionIsReportedOnItsCommit(): void
    {
        $replay     = $this->replayableToken();
        $connection = DB::connection(SeparateConnectionDevice::CONNECTION);

        $connection->beginTransaction();

        self::assertNull($this->guard()->refresh($replay));

        $connection->rollBack();

        self::assertSame(['Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());
        self::assertNull($this->row($this->device())['revoked_at']);

        $this->dispatched->exchangeArray([]);

        $connection->beginTransaction();

        self::assertNull($this->guard()->refresh($replay));
        self::assertSame(['Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());

        $connection->commit();

        self::assertSame(['Failed', 'AuthenticationFailed', 'DeviceRevoked'], $this->dispatched->getArrayCopy());
        self::assertSame('rotation_reuse', $this->row($this->device())['revoked_reason']);
    }

    /**
     * A revocation made inside a nested transaction on the device's own
     * connection that is rolled back is never reported, even though the outer
     * transaction then commits, and the device stays live.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testReplayRolledBackWithANestedTransactionIsNeverReported(): void
    {
        $replay     = $this->replayableToken();
        $connection = DB::connection(SeparateConnectionDevice::CONNECTION);

        $connection->beginTransaction();
        $connection->beginTransaction();

        self::assertNull($this->guard()->refresh($replay));

        $connection->rollBack();
        $connection->commit();

        self::assertSame(['Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());
        self::assertNull($this->row($this->device())['revoked_at']);
    }

    /**
     * A refresh is reported once its rotation is committed on the device's own
     * connection: at once while only another connection has a transaction open,
     * and that transaction rolling back does not withdraw it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testRefreshIsReportedAtOnceWhateverAnotherConnectionsTransactionDoes(): void
    {
        [$identity, $device] = $this->signIn();

        DB::beginTransaction();

        self::assertNotNull($this->guard()->refresh($this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity)));
        self::assertSame(['Refreshed'], $this->dispatched->getArrayCopy());

        DB::rollBack();

        self::assertSame(['Refreshed'], $this->dispatched->getArrayCopy());
    }

    /**
     * Inside a transaction on the device's own connection a refresh is reported
     * only when that transaction commits, and never when it rolls back, which
     * also leaves the presented token current.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testRefreshInsideTheDeviceConnectionsTransactionIsReportedOnItsCommit(): void
    {
        [$identity, $device] = $this->signIn();

        $token      = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $connection = DB::connection(SeparateConnectionDevice::CONNECTION);

        $connection->beginTransaction();

        self::assertNotNull($this->guard()->refresh($token));

        $connection->rollBack();

        self::assertSame([], $this->dispatched->getArrayCopy());
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->row($device)['refresh_key']);

        $connection->beginTransaction();

        self::assertNotNull($this->guard()->refresh($token));
        self::assertSame([], $this->dispatched->getArrayCopy());

        $connection->commit();

        self::assertSame(['Refreshed'], $this->dispatched->getArrayCopy());
    }

    /**
     * Keep the devices on their own connection, a separate database, and
     * configure the `api` guard.
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

        $config->set('database.connections.' . SeparateConnectionDevice::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authentication.device.model', SeparateConnectionDevice::class);
        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparateConnectionDeviceIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'jwt' => ['refresh_grace_seconds' => 30]]);
    }

    /**
     * Persist an identity signed in on a new device holding `ROTATION_ID`.
     *
     * @return array{0: \Tests\Integration\Fixtures\SeparateConnectionDeviceIdentity, 1: \Tests\Integration\Fixtures\SeparateConnectionDevice}
     */
    private function signIn(): array
    {
        $identity            = new SeparateConnectionDeviceIdentity;
        $identity->email     = 'separate@example.test';
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        $device = new SeparateConnectionDevice;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return [$identity, $device];
    }

    /**
     * Sign in, rotate the device's row past `ROTATION_ID` an hour ago, and
     * return a validly signed refresh token carrying `ROTATION_ID`, which is
     * now a replay.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function replayableToken(): string
    {
        [$identity, $device] = $this->signIn();

        DB::connection(SeparateConnectionDevice::CONNECTION)->table('devices')->where('id', $device->id)->update([
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)),
            'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID),
            'refresh_rotated_at'   => $this->now->copy()->subHour()->format('Y-m-d H:i:s'),
        ]);

        return $this->tokens()->issueRefreshToken($this->device(), self::ROTATION_ID, $identity);
    }

    /**
     * The one device, loaded from its own connection.
     *
     * @return \Tests\Integration\Fixtures\SeparateConnectionDevice
     */
    private function device(): SeparateConnectionDevice
    {
        return SeparateConnectionDevice::query()->sole();
    }

    /**
     * Read a device's raw row from its own connection.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionDevice  $device
     * @return array<string, mixed>
     */
    private function row(SeparateConnectionDevice $device): array
    {
        return (array) DB::connection(SeparateConnectionDevice::CONNECTION)->table('devices')->where('id', $device->id)->first();
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
     * A fresh `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(): JwtGuard
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        $guard = $manager->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
