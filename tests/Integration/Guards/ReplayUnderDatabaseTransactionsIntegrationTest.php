<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * End-to-end tests for replay revocation in an application's own test suite,
 * which wraps every test in a transaction with Laravel's `DatabaseTransactions`
 * trait: that wrapping transaction never commits, so `DeviceRevoked` must not
 * wait for it, yet a transaction the application opens inside it still defers
 * the event until it commits.
 *
 * The tables are created before the wrapping transaction begins and dropped
 * after it is rolled back, so the schema neither commits it early on MySQL nor
 * survives the test on PostgreSQL, where it would be rolled back with it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceRevoked::class)]
#[CoversClass(RefreshRotationStore::class)]
final class ReplayUnderDatabaseTransactionsIntegrationTest extends TestCase
{
    use DatabaseTransactions, InteractsWithDevices;

    /** @var string Plaintext rotation id of the device's first refresh token. */
    private const string ROTATION_ID = 'first-rotation-id';

    /** @var string Path of the shipped devices migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000000_create_devices_table.php';

    /** @var string Path of the shipped rate limits migration, whose table the refresh exchange counts failures in. */
    private const string RATE_LIMITS_MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_04_06_000002_create_rate_limits_table.php';

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Events\DeviceRevoked> Revocations reported so far. */
    private \ArrayObject $revoked;

    /**
     * Freeze the clocks and record every `DeviceRevoked` event.
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

        $this->revoked = new \ArrayObject;

        Event::listen(DeviceRevoked::class, function (DeviceRevoked $event): void {
            $this->revoked->append($event);
        });
    }

    /**
     * Release the frozen clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A replay outside any transaction of the application's own is reported at
     * once, although the test's wrapping transaction is still open and will
     * never commit.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReplayOutsideTheApplicationsTransactionsIsReportedAtOnce(): void
    {
        $device = $this->replayedDevice();

        self::assertInstanceOf(DatabaseTransactionsManager::class, app('db.transactions'));
        self::assertSame(1, DB::transactionLevel());

        self::assertNull(GuardSessions::of($this->guard())->refresh($this->replay($device))->session);
        self::assertSame([$device->getKey()], array_map(
            static fn (DeviceRevoked $event): mixed => $event->context->deviceId,
            $this->revoked->getArrayCopy(),
        ));
        self::assertSame('rotation_reuse', $this->stored($device)->getRevokedReason());
    }

    /**
     * A replay inside a transaction the application opens within the test's
     * wrapping one is reported when that transaction commits, and never when it
     * is rolled back, which also leaves the device live.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testReplayInsideTheApplicationsTransactionIsReportedWhenItCommits(): void
    {
        $device = $this->replayedDevice();
        $replay = $this->replay($device);

        DB::beginTransaction();

        self::assertNull(GuardSessions::of($this->guard())->refresh($replay)->session);

        DB::rollBack();

        self::assertCount(0, $this->revoked);
        self::assertNull($this->stored($device)->getRevokedAt());

        DB::beginTransaction();

        self::assertNull(GuardSessions::of($this->guard())->refresh($replay)->session);
        self::assertCount(0, $this->revoked);

        DB::commit();

        self::assertCount(1, $this->revoked);
        self::assertSame('rotation_reuse', $this->stored($device)->getRevokedReason());
    }

    /**
     * Create the shipped devices and rate limits tables and the identity table
     * before the wrapping transaction begins. Teardown callbacks run in reverse
     * order, so on a persistent database the tables are dropped after the
     * wrapping transaction is rolled back; an in-memory one goes with its
     * connection.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        foreach ([self::MIGRATION_PATH, self::RATE_LIMITS_MIGRATION_PATH] as $path) {

            $migration = include $path;

            \call_user_func([$migration, 'up']);
        }

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        if ((getenv('DB_CONNECTION') ?: 'sqlite') === 'sqlite') {
            return;
        }

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::dropIfExists('stub_principals');
            Schema::dropIfExists('devices');
            Schema::dropIfExists('rate_limits');
        });
    }

    /**
     * Configure the `api` guard with a grace window.
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
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => StubPrincipal::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'jwt' => ['refresh_grace_seconds' => 30]]);
        $config->set('authentication.device.last_used_throttle_seconds', 3600);
    }

    /**
     * Persist an identity with a live device whose `ROTATION_ID` was replaced
     * an hour ago, so presenting it again is a replay.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function replayedDevice(): Device
    {
        $identity            = new StubPrincipal;
        $identity->email     = 'replay@example.test';
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)),
            'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID),
            'refresh_rotated_at'   => $this->now->copy()->subHour(),
            'last_used_at'         => $this->now,
        ])->save();

        return $device;
    }

    /**
     * A validly signed refresh token for the device carrying the replaced
     * `ROTATION_ID`.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return string
     */
    private function replay(Device $device): string
    {
        return $this->tokens()->issueRefreshToken($this->stored($device), self::ROTATION_ID);
    }

    /**
     * Reload a device from the database.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function stored(Device $device): Device
    {
        return Device::query()->whereKey($device->getKey())->firstOrFail();
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
