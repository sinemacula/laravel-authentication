<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * End-to-end tests for refresh replay detection on the shipped devices table,
 * through the guard, the facade, and HTTP: parallel refreshes with one token,
 * replays that revoke the device and end its access tokens, recovery from a
 * lost response, revocation reported only after commit, and refresh inside a
 * caller's transaction on each engine.
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
final class RefreshReplayIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Plaintext rotation id of the device's first refresh token. */
    private const string ROTATION_ID = 'first-rotation-id';

    /** @var string Second connection to the same database, for a competing request. */
    private const string COMPETITOR = 'competitor';

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /**
     * Freeze the clocks, create the identity table, and register a route behind
     * the `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        $this->moveClockTo($this->now);

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
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
     * Two refreshes with the same token race: the second rotates the device
     * between the first one's read and its swap. Both succeed with the same
     * current credential, and the device stays live.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParallelRefreshesWithOneTokenBothGetTheCurrentCredential(): void
    {
        [$identity, $device] = $this->signIn();

        $token  = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $winner = null;

        $this->beforeTheSwap(function () use ($token, &$winner): void {
            $winner = GuardSessions::of($this->guard())->refresh($token)->session?->tokens;
        });

        $loser = GuardSessions::of($this->guard())->refresh($token)->session?->tokens;

        self::assertInstanceOf(TokenPair::class, $winner);
        self::assertInstanceOf(TokenPair::class, $loser);
        self::assertSame(RefreshTokenHasher::successor(self::ROTATION_ID), $this->claims($winner->refreshToken)[Claims::JWT_ID->value]);
        self::assertSame($this->claims($winner->refreshToken)[Claims::JWT_ID->value], $this->claims($loser->refreshToken)[Claims::JWT_ID->value]);
        self::assertNull($this->stored($device)->getRevokedAt());
        self::assertSame(RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)), $this->stored($device)->getRefreshKey());
    }

    /**
     * With grace disabled, the request that loses the race holds a replaced
     * token: it is treated as a replay and the device is revoked.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testParallelRefreshesWithGraceDisabledRevokeTheDevice(): void
    {
        config()->set('auth.guards.api.jwt.refresh_grace_seconds', 0);

        [$identity, $device] = $this->signIn();

        $token  = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $winner = null;

        $this->beforeTheSwap(function () use ($token, &$winner): void {
            $winner = GuardSessions::of($this->guard())->refresh($token)->session?->tokens;
        });

        self::assertNull(GuardSessions::of($this->guard())->refresh($token)->session);
        self::assertInstanceOf(TokenPair::class, $winner);
        self::assertSame('rotation_reuse', $this->stored($device)->getRevokedReason());
    }

    /**
     * A refresh token presented after the grace window of the rotation that
     * replaced it revokes the device: `DeviceRevoked` is dispatched once with
     * `AuthenticationFailed`, and the device's access tokens stop working at
     * once, through the `auth` middleware, each request reporting the revoked
     * device.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReplayRevokesTheDeviceAndEndsItsAccessTokens(): void
    {
        [$identity, $device] = $this->signIn();

        $stolen = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $pair   = GuardSessions::of($this->guard())->refresh($stolen)->session?->tokens;

        self::assertNotNull($pair);

        $this->bearer($pair->accessToken)->assertOk();

        $this->moveClockTo($this->now->copy()->addMinute());

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Events\DeviceRevoked> $revoked */
        $revoked = new \ArrayObject;

        /** @var \ArrayObject<int, array{0: \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}> $failed */
        $failed = new \ArrayObject;

        Event::listen(DeviceRevoked::class, static function (DeviceRevoked $event) use ($revoked): void {
            $revoked->append($event);
        });
        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use ($failed): void {
            $failed->append([$event->flow, $event->reason]);
        });

        self::assertNull(GuardSessions::of($this->guard())->refresh($stolen)->session);
        self::assertCount(1, $revoked);
        self::assertSame($device->getKey(), $revoked->getArrayCopy()[0]->context->device?->getDeviceIdentifier());
        self::assertSame([[AuthenticationFlow::REFRESH, FailureReason::ROTATION_REUSE]], $failed->getArrayCopy());

        $this->bearer($pair->accessToken)->assertUnauthorized();

        self::assertNull(GuardSessions::of($this->guard())->refresh($pair->refreshToken)->session);
        self::assertSame([
            [AuthenticationFlow::REFRESH, FailureReason::ROTATION_REUSE],
            [AuthenticationFlow::BEARER, FailureReason::DEVICE_REVOKED],
            [AuthenticationFlow::REFRESH, FailureReason::DEVICE_REVOKED],
        ], $failed->getArrayCopy());
        self::assertCount(1, $revoked);
    }

    /**
     * A rotation and a replay change only the device they concern. Another
     * device of the same identity, and a device of another identity that holds
     * the same rotation id digest, keep their digests, rotation time, and
     * deadlines through both, stay live, and still authenticate through the
     * `auth` middleware and refresh.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotationAndReplayTouchOnlyTheirOwnDevice(): void
    {
        [$identity, $device]       = $this->signIn();
        [$stranger, $sameRotation] = $this->signIn('stranger@example.test');

        $sibling = $this->addDevice($identity, 'sibling-rotation-id');
        $others  = [$sibling, $sameRotation];
        $before  = array_map($this->rawRow(...), $others);

        $stolen = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);

        self::assertNotNull(GuardSessions::of($this->guard())->refresh($stolen)->session);
        self::assertSame($before, array_map($this->rawRow(...), $others));

        $this->moveClockTo($this->now->copy()->addMinute());

        self::assertNull(GuardSessions::of($this->guard())->refresh($stolen)->session);
        self::assertSame('rotation_reuse', $this->stored($device)->getRevokedReason());
        self::assertSame($before, array_map($this->rawRow(...), $others));

        foreach ([[$identity, $sibling, 'sibling-rotation-id'], [$stranger, $sameRotation, self::ROTATION_ID]] as [$owner, $other, $rotationId]) {

            $this->bearer($this->tokens()->issueAccessToken($owner, $owner, $other))->assertOk()->assertJson(['device' => $other->getKey()]);

            self::assertNotNull(GuardSessions::of($this->guard())->refresh($this->tokens()->issueRefreshToken($other, $rotationId, $owner))->session);
            self::assertNull($this->stored($other)->getRevokedAt());
        }
    }

    /**
     * A refresh whose response is lost after the rotation committed, here
     * through a listener that throws, is recoverable: a retry inside the grace
     * window gets the current credential; after the window the same token is a
     * replay.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testLostResponseIsRecoverableInsideTheGraceWindowOnly(): void
    {
        [$identity, $device] = $this->signIn();

        $token  = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $failed = false;

        Event::listen(Refreshed::class, static function () use (&$failed): void {
            if (!$failed) {
                $failed = true;

                throw new \RuntimeException('listener failed');
            }
        });

        try {
            GuardSessions::of($this->guard())->refresh($token);

            self::fail('The listener failure should have propagated.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        $this->moveClockTo($this->now->copy()->addSeconds(20));

        $retry = GuardSessions::of($this->guard())->refresh($token)->session?->tokens;

        self::assertNotNull($retry);
        self::assertSame(RefreshTokenHasher::successor(self::ROTATION_ID), $this->claims($retry->refreshToken)[Claims::JWT_ID->value]);

        $this->moveClockTo($this->now->copy()->addSeconds(30));

        self::assertNull(GuardSessions::of($this->guard())->refresh($token)->session);
        self::assertSame('rotation_reuse', $this->stored($device)->getRevokedReason());
    }

    /**
     * A revocation made inside a transaction is reported only once the
     * transaction commits; one that is rolled back is never reported and leaves
     * the device live.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testRevocationIsReportedOnlyAfterCommit(): void
    {
        [$identity, $device] = $this->signIn();

        $this->rotateOnTheRow($device, $this->now->copy()->subHour());

        $replay = $this->tokens()->issueRefreshToken($this->stored($device), self::ROTATION_ID, $identity);

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Events\DeviceRevoked> $revoked */
        $revoked = new \ArrayObject;

        Event::listen(DeviceRevoked::class, static function (DeviceRevoked $event) use ($revoked): void {
            $revoked->append($event);
        });

        DB::beginTransaction();

        self::assertNull(GuardSessions::of($this->guard())->refresh($replay)->session);
        self::assertCount(0, $revoked);

        DB::rollBack();

        self::assertCount(0, $revoked);
        self::assertNull($this->stored($device)->getRevokedAt());

        DB::transaction(fn () => GuardSessions::of($this->guard())->refresh($replay));

        self::assertCount(1, $revoked);
        self::assertSame('rotation_reuse', $this->stored($device)->getRevokedReason());
    }

    /**
     * Inside a caller's REPEATABLE READ transaction, a parallel refresh that
     * commits between this refresh's read and its swap is handled as the engine
     * allows: MySQL's locking re-read sees the committed rotation, so this
     * refresh is a grace retry; PostgreSQL refuses the swap with a
     * serialization failure, which propagates as a server error for the caller
     * to retry, and nothing is revoked.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testParallelRefreshInsideARepeatableReadTransaction(): void
    {
        $driver = DB::connection()->getDriverName();

        if ($driver === 'sqlite') {
            self::markTestSkipped('SQLite serialises writers; there is no concurrent transaction to race.');
        }

        [$identity, $device] = $this->signIn();

        $token = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);

        $this->beforeTheSwap(function () use ($device): void {
            DB::connection(self::COMPETITOR)->table('devices')->where('id', $device->getKey())->update([
                'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)),
                'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID),
                'refresh_rotated_at'   => $this->now->format('Y-m-d H:i:s'),
            ]);
        });

        DB::beginTransaction();

        if ($driver === 'pgsql') {
            DB::statement('set transaction isolation level repeatable read');
        }

        try {
            $result = GuardSessions::of($this->guard())->refresh($token)->session?->tokens;

            DB::commit();
        } catch (QueryException $exception) {
            DB::rollBack();

            self::assertSame('pgsql', $driver);
            self::assertSame('40001', $exception->getCode());
            self::assertNull(DB::connection(self::COMPETITOR)->table('devices')->where('id', $device->getKey())->value('revoked_at'));

            return;
        }

        self::assertSame('mysql', $driver);
        self::assertNotNull($result);
        self::assertSame(RefreshTokenHasher::successor(self::ROTATION_ID), $this->claims($result->refreshToken)[Claims::JWT_ID->value]);
    }

    /**
     * Configure the `api` guard and a second connection to the same database.
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

        $config->set('database.connections.' . self::COMPETITOR, $config->get('database.connections.testing'));
        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => StubPrincipal::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'jwt' => ['refresh_grace_seconds' => 30]]);
        $config->set('authentication.device.last_used_throttle_seconds', 3600);
    }

    /**
     * Persist an identity signed in on a new device holding `ROTATION_ID`.
     *
     * @param  string  $email
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Device}
     */
    private function signIn(string $email = 'replay@example.test'): array
    {
        $identity            = new StubPrincipal;
        $identity->email     = $email;
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        return [$identity, $this->addDevice($identity, self::ROTATION_ID)];
    }

    /**
     * Persist a live device of the identity holding the given rotation id.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  string  $rotationId
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function addDevice(StubPrincipal $identity, string $rotationId): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        return $device;
    }

    /**
     * Read a device's raw row.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return array<string, mixed>
     */
    private function rawRow(Device $device): array
    {
        return (array) DB::table('devices')->where('id', $device->getKey())->first();
    }

    /**
     * Rotate the device's row from `ROTATION_ID` to its successor at the given
     * time.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @param  \Carbon\Carbon  $rotatedAt
     * @return void
     */
    private function rotateOnTheRow(Device $device, Carbon $rotatedAt): void
    {
        Device::query()->whereKey($device->getKey())->update([
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)),
            'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID),
            'refresh_rotated_at'   => $rotatedAt,
        ]);
    }

    /**
     * Run a callback once, just before the first compare-and-swap executes on
     * the default connection.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function beforeTheSwap(\Closure $callback): void
    {
        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $callback): void {
            if ($ran || !str_starts_with(strtolower($query), 'update') || !str_contains($query, 'refresh_rotated_at')) {
                return;
            }

            $ran = true;

            $callback();
        });
    }

    /**
     * Send a bearer request to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');
    }

    /**
     * Decode a refresh token's claims.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    private function claims(#[\SensitiveParameter] string $token): array
    {
        $claims = $this->tokens()->parse($token, TokenType::REFRESH);

        self::assertIsArray($claims);

        return $claims;
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
