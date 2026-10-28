<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Query-budget contracts for the refresh-token exchange hot paths.
 *
 * Every refresh first reads its device's and its IP address's refresh limits in
 * one query. A failed refresh then counts the failure against both: on a fresh
 * window, for each counter, an update that changes nothing and the insert that
 * creates it, so four writes. A successful refresh writes nothing to the
 * limits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(RefreshRotationStore::class)]
final class RefreshTokenExchangeQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithDevices;

    /** @var string Guard name for standard refresh tests. */
    private const string GUARD = 'api';

    /** @var int Runs of each path in the timing comparison. */
    private const int TIMED_RUNS = 5;

    /** @var int How many times slower than a rotation the other paths may be. */
    private const int TIMING_FACTOR = 3;

    /** @var string Guard name for tenant-aware refresh tests. */
    private const string TENANT_AWARE_GUARD = 'tenant_api';

    /**
     * Provision the identity table used by the refresh fixtures.
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
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the fixture table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('tenant_aware_3d_principals');
        Schema::dropIfExists('tenant_aware_3d_tenants');
        Schema::dropIfExists('tenant_aware_3d_identities');
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * Refresh success should read its limits, do the device lookup and
     * authenticatable hydration, then one CAS write. The timestamp write is
     * suppressed here by seeding `last_used_at` inside the throttle window.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshSuccessUsesThreeReadsAndOneWrite(): void
    {
        $identity   = $this->seedIdentity();
        $rotationId = 'refresh-success-rotation-id';

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, $rotationId, $identity);
        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(3, 1, static fn () => $guard->refresh($token));

        self::assertNotNull($result);
    }

    /**
     * Unknown-device refresh failures should stop at the first device lookup,
     * then count the failure.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUnknownDeviceRefreshFailureStopsAtTheDeviceLookup(): void
    {
        $missingDevice = new Device;
        $missingDevice->forceFill([...self::liveSession(), 'id' => '00000000-0000-0000-0000-000000000000']);

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($missingDevice, 'missing-device-rotation');

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(2, 4, static fn () => $guard->refresh($token));

        self::assertNull($result);
    }

    /**
     * A device id that cannot be a key of the device model is rejected before
     * the device lookup, so the failure costs only the limits' read and its
     * count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMalformedDeviceIdRefreshFailureSkipsTheDeviceLookup(): void
    {
        $malformedDevice = new Device;
        $malformedDevice->forceFill([...self::liveSession(), 'id' => 'not-a-uuid']);

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($malformedDevice, 'malformed-device-rotation');

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(1, 4, static fn () => $guard->refresh($token));

        self::assertNull($result);
    }

    /**
     * A replayed refresh token is judged from the device row alone, before the
     * owner is loaded, and costs the device read plus the one guarded
     * revocation write, besides the limits' read and the failure's count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReplayRevocationReadsTheDeviceAndRevokesItInOneWrite(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, ['refresh_key' => RefreshTokenHasher::hash('stored-rotation-id')]);

        $token = $this->tokens()->issueRefreshToken($device, 'replayed-rotation-id');
        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertNull($this->assertQueryBudget(2, 5, static fn () => $guard->refresh($token)));
        self::assertSame('rotation_reuse', Device::query()->whereKey($device->getKey())->firstOrFail()->getRevokedReason());
    }

    /**
     * A grace retry is answered from the limits, the device row and the owner
     * with no write at all: the current credential is re-issued, not rotated
     * again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGraceRetryUsesThreeReadsAndNoWrites(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, [
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor('previous-rotation-id')),
            'previous_refresh_key' => RefreshTokenHasher::hash('previous-rotation-id'),
            'refresh_rotated_at'   => $this->now->copy()->subSeconds(5),
            'last_used_at'         => $this->now,
        ]);

        $token = $this->tokens()->issueRefreshToken($device, 'previous-rotation-id', $identity);
        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertNotNull($this->assertQueryBudget(3, 0, static fn () => $guard->refresh($token)));
    }

    /**
     * A refresh that loses its swap to a parallel refresh with the same token
     * pays the limits, device and owner reads, the missed swap, and one locking
     * re-read of the device, then succeeds as a grace retry.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLostRotationResolvedAsAGraceRetryUsesFourReadsAndOneWrite(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, [
            'refresh_key'  => RefreshTokenHasher::hash('raced-rotation-id'),
            'last_used_at' => $this->now,
        ]);

        $token = $this->tokens()->issueRefreshToken($device, 'raced-rotation-id', $identity);
        $guard = $this->freshJwtGuard(self::GUARD);
        $ran   = false;

        DB::connection()->beforeExecuting(function (string $query) use (&$ran, $device): void {
            if ($ran || !str_contains($query, 'refresh_rotated_at')) {
                return;
            }

            $ran = true;

            // The winning request's rotation, written past the query log so
            // only this request's own queries count against its budget.
            DB::connection()->getPdo()
                ->prepare('update devices set refresh_key = ?, previous_refresh_key = ?, refresh_rotated_at = ? where id = ?')
                ->execute([
                    RefreshTokenHasher::hash(RefreshTokenHasher::successor('raced-rotation-id')),
                    RefreshTokenHasher::hash('raced-rotation-id'),
                    $this->now->format('Y-m-d H:i:s'),
                    $device->getKey(),
                ]);
        });

        self::assertNotNull($this->assertQueryBudget(4, 1, static fn () => $guard->refresh($token)));
    }

    /**
     * A refresh for a device that holds no refresh credential stops at the
     * device lookup and writes nothing but the failure's count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMissingRefreshCredentialStopsAtTheDeviceLookup(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, ['refresh_key' => null]);

        $token  = $this->tokens()->issueRefreshToken($device, 'any-rotation-id');
        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull($this->assertQueryBudget(2, 4, static fn () => $guard->refresh($token)));
        self::assertSame([[FailureReason::REFRESH_KEY_MISSING, $device->getKey()]], self::failures($events));
    }

    /**
     * A refresh replaying a token against a device already revoked for reuse
     * stops at the device lookup: it revokes nothing again, and writes nothing
     * but the failure's count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRevokedDeviceRefreshFailureStopsAtTheDeviceLookup(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, [
            'refresh_key'          => null,
            'previous_refresh_key' => null,
            'revoked_at'           => $this->now->copy()->subMinute(),
            'revoked_reason'       => 'rotation_reuse',
        ]);

        $token  = $this->tokens()->issueRefreshToken($device, 'replayed-rotation-id', $identity);
        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull($this->assertQueryBudget(2, 4, static fn () => $guard->refresh($token)));
        self::assertSame([[FailureReason::DEVICE_REVOKED, $device->getKey()]], self::failures($events));
    }

    /**
     * The grace and replay paths cost no more than a rotation: each compares at
     * most two digests and derives one successor, with no loop over past
     * rotations. Measured as the fastest of several runs of each path against
     * the fastest rotation, with a generous factor for noise.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testGraceAndReplayCostNoMoreThanARotation(): void
    {
        $identity = $this->seedIdentity();
        $fastest  = ['current' => PHP_INT_MAX, 'grace' => PHP_INT_MAX, 'replay' => PHP_INT_MAX];

        for ($run = 0; $run < self::TIMED_RUNS; $run++) {
            foreach (array_keys($fastest) as $path) {

                $token = $this->tokenForPath($identity, $path, "timed-{$path}-{$run}");
                $guard = $this->freshJwtGuard(self::GUARD);

                $started = hrtime(true);
                $result  = $guard->refresh($token);
                $elapsed = hrtime(true) - $started;

                self::assertSame($path !== 'replay', $result !== null, $path);

                $fastest[$path] = min($fastest[$path], $elapsed);
            }
        }

        self::assertLessThan(self::TIMING_FACTOR * $fastest['current'], $fastest['grace']);
        self::assertLessThan(self::TIMING_FACTOR * $fastest['current'], $fastest['replay']);
    }

    /**
     * A refresh for a device whose session has ended stops at the device
     * lookup: the deadlines are read from the loaded row, and nothing but the
     * failure's count is written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEndedSessionRefreshFailureStopsAtTheDeviceLookup(): void
    {
        $identity   = $this->seedIdentity();
        $rotationId = 'ended-session-rotation-id';

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
        ])->save();

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, $rotationId, $identity);

        $device->forceFill(['idle_expires_at' => $this->now])->save();

        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull($this->assertQueryBudget(2, 4, static fn () => $guard->refresh($token)));
        self::assertSame([[FailureReason::SESSION_EXPIRED, $device->getKey()]], self::failures($events));
    }

    /**
     * A refresh for a device of another guard is refused from the device row,
     * before the owner is loaded: the limits' read, the device read, and the
     * failure's count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGuardMismatchRefreshFailureStopsAtTheDeviceLookup(): void
    {
        $device = $this->seedDevice($this->seedIdentity(), ['guard' => 'other', 'refresh_key' => RefreshTokenHasher::hash('other-guard-rotation-id')]);
        $token  = $this->tokens()->issueRefreshToken($device, 'other-guard-rotation-id');
        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull($this->assertQueryBudget(2, 4, static fn () => $guard->refresh($token)));
        self::assertSame([[FailureReason::DEVICE_GUARD_MISMATCH, $device->getKey()]], self::failures($events));
    }

    /**
     * A refresh whose session began with a method the guard no longer allows is
     * refused once the owner is loaded, before any rotation write.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisallowedMethodRefreshFailureStopsBeforeTheRotation(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, ['sign_in_method' => 'sso', 'refresh_key' => RefreshTokenHasher::hash('sso-rotation-id')]);
        $token    = $this->tokens()->issueRefreshToken($device, 'sso-rotation-id', $identity);
        $guard    = $this->freshJwtGuard(self::GUARD);
        $events   = $this->recordRefreshEvents();

        self::assertNull($this->assertQueryBudget(3, 4, static fn () => $guard->refresh($token)));
        self::assertSame([[FailureReason::METHOD_NOT_ALLOWED, $device->getKey()]], self::failures($events));
    }

    /**
     * A refresh for a principal the guard's audience no longer admits is
     * refused once the owner is loaded, before any rotation write.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIneligiblePrincipalRefreshFailureStopsBeforeTheRotation(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, ['refresh_key' => RefreshTokenHasher::hash('ineligible-rotation-id')]);
        $token    = $this->tokens()->issueRefreshToken($device, 'ineligible-rotation-id', $identity);

        app(ConfigRepository::class)->set('auth.guards.' . self::GUARD . '.audience', ['principal_types' => ['staff']]);

        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull($this->assertQueryBudget(3, 4, static fn () => $guard->refresh($token)));
        self::assertSame([[FailureReason::PRINCIPAL_INELIGIBLE, $device->getKey()]], self::failures($events));
    }

    /**
     * A refresh for a device that has used up its failures is refused from the
     * limits' read alone, with a 429 and nothing written, so a flood of them
     * never reaches the device.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRateLimitedRefreshIsRefusedFromTheLimitsAlone(): void
    {
        $device = $this->seedDevice($this->seedIdentity(), ['refresh_key' => RefreshTokenHasher::hash('limited-rotation-id')]);
        $token  = $this->tokens()->issueRefreshToken($device, 'limited-rotation-id');

        $limits = ['refresh' => ['per_identifier' => ['max' => 1, 'decay_seconds' => 60], 'per_ip' => null]];

        app(ConfigRepository::class)->set('auth.guards.' . self::GUARD . '.rate_limits', $limits);

        $guard = $this->freshJwtGuard(self::GUARD);

        app(AttemptLimiter::class)->recordFailure(new AttemptSubject(self::GUARD, AttemptFlow::REFRESH, (string) $device->getKey(), null, null)); // @phpstan-ignore cast.string

        $events = $this->recordRefreshEvents();
        $thrown = $this->assertQueryBudget(1, 0, static function () use ($guard, $token): ?\Throwable {
            try {
                $guard->refresh($token);
            } catch (ThrottleRequestsException $e) {
                return $e;
            }

            return null;
        });

        self::assertInstanceOf(ThrottleRequestsException::class, $thrown);
        self::assertCount(1, $events);
        self::assertSame(FailureReason::RATE_LIMITED, $events[0]->reason ?? null);
    }

    /**
     * Tenant-aware 3D refresh success should pay exactly the limits' read, the
     * device read, the authenticatable read, the joined principal+tenant read,
     * and one rotation write.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPathWithTenantAccessUsesFourReadsAndOneWrite(): void
    {
        [$identity, $principal] = $this->seedTenantAwareThreeDimensionalFixtures();
        $rotationId             = 'refresh-tenant-aware-success';

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(self::TENANT_AWARE_GUARD),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, $rotationId, $principal);
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(4, 1, static function () use ($guard, $token): ?RefreshResult {
            $tokens = $guard->refresh($token);
            $guard->principal()?->getIdentity();
            $guard->tenant();
            $guard->type();

            return $tokens;
        });

        self::assertNotNull($result);
    }

    /**
     * A tenant-aware refresh for a secondary tenant hint should still pay the
     * same limits + device + identity + joined principal read budget as the
     * primary tenant path.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPathWithSecondaryTenantHintUsesFourReadsAndOneWrite(): void
    {
        [$identity, , $secondaryPrincipal] = $this->seedTenantAwareThreeDimensionalFixturesWithSecondaryTenant();
        $rotationId                        = 'refresh-tenant-aware-secondary-success';

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(self::TENANT_AWARE_GUARD),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, $rotationId, $secondaryPrincipal);
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(4, 1, static function () use ($guard, $token): ?RefreshResult {
            $tokens = $guard->refresh($token);
            $guard->principal()?->getIdentity();
            $guard->tenant();
            $guard->type();

            return $tokens;
        });

        self::assertNotNull($result);
        self::assertSame($secondaryPrincipal->getPrincipalIdentifier(), $guard->principal()?->getPrincipalIdentifier());
        self::assertSame('customer', $guard->type());
    }

    /**
     * A failure on the 3D pid path must still stop before the rotation write;
     * it writes only the failure's count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPidFailureStopsBeforeRotationWrite(): void
    {
        [
            $identity,
            $principal
        ]           = $this->seedTenantAwareThreeDimensionalFixtures('refresh-tenant-aware-failure@example.test', false);
        $rotationId = 'refresh-tenant-aware-failure';

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(self::TENANT_AWARE_GUARD),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, $rotationId, $principal);
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(4, 4, static function () use ($guard, $token): ?RefreshResult {
            $tokens = $guard->refresh($token);
            $guard->tenant();

            return $tokens;
        });

        self::assertNull($result);
    }

    /**
     * Configure the single JWT guard used by this test.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', self::GUARD);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.guards.' . self::TENANT_AWARE_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'tenant_aware_identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('auth.providers.tenant_aware_identities', [
            'driver' => 'model',
            'model'  => TenantAware3dIdentity::class,
        ]);

        $config->set('authentication.device.last_used_throttle_seconds', 60);
    }

    /**
     * Persist and return an active identity that is also the acting principal.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedIdentity(): StubPrincipal
    {
        $identity            = new StubPrincipal;
        $identity->email     = 'refresh-performance@example.test';
        $identity->password  = password_hash('correct horse battery staple', PASSWORD_BCRYPT);
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Persist and return a tenant-aware 3D identity and hinted principal.
     *
     * @formatter:off
     *
     * @param  string  $email
     * @param  bool  $principalActive
     * @return array{0: \Tests\Integration\Fixtures\TenantAware3dIdentity, 1: \Tests\Integration\Fixtures\TenantAware3dPrincipal}
     *
     * @formatter:on
     */
    private function seedTenantAwareThreeDimensionalFixtures(string $email = 'refresh-tenant-aware@example.test', bool $principalActive = true): array
    {
        $identity            = new TenantAware3dIdentity;
        $identity->email     = $email;
        $identity->password  = password_hash('correct horse battery staple', PASSWORD_BCRYPT);
        $identity->is_active = true;
        $identity->save();

        $tenant       = new TenantAware3dTenant;
        $tenant->name = 'Refresh Staff';
        $tenant->type = 'staff';
        $tenant->save();

        $principal              = new TenantAware3dPrincipal;
        $principal->identity_id = $identity->getKey(); // @phpstan-ignore assign.propertyType
        $principal->tenant_id   = $tenant->getKey(); // @phpstan-ignore assign.propertyType
        $principal->name        = 'refresh-staff-actor';
        $principal->is_active   = $principalActive;
        $principal->save();

        return [$identity, $principal];
    }

    /**
     * Persist and return a tenant-aware 3D identity with active principals for
     * two separate tenant types.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\TenantAware3dIdentity, 1: \Tests\Integration\Fixtures\TenantAware3dPrincipal, 2: \Tests\Integration\Fixtures\TenantAware3dPrincipal}
     *
     * @formatter:on
     */
    private function seedTenantAwareThreeDimensionalFixturesWithSecondaryTenant(string $email = 'refresh-tenant-aware-secondary@example.test'): array
    {
        [$identity, $primaryPrincipal] = $this->seedTenantAwareThreeDimensionalFixtures($email);

        $secondaryTenant       = new TenantAware3dTenant;
        $secondaryTenant->name = 'Refresh Customer';
        $secondaryTenant->type = 'customer';
        $secondaryTenant->save();

        $secondaryPrincipal              = new TenantAware3dPrincipal;
        $secondaryPrincipal->identity_id = $identity->getKey(); // @phpstan-ignore assign.propertyType
        $secondaryPrincipal->tenant_id   = $secondaryTenant->getKey(); // @phpstan-ignore assign.propertyType
        $secondaryPrincipal->name        = 'refresh-customer-actor';
        $secondaryPrincipal->is_active   = true;
        $secondaryPrincipal->save();

        return [$identity, $primaryPrincipal, $secondaryPrincipal];
    }

    /**
     * Persist a live device owned by the identity, with any further state.
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
     * Record every `AuthenticationFailed` and `DeviceRevoked` event dispatched
     * from here on.
     *
     * @return \ArrayObject<int, object>
     */
    private function recordRefreshEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, object> $events */
        $events = new \ArrayObject;

        Event::listen([AuthenticationFailed::class, DeviceRevoked::class], static function (object $event) use ($events): void {
            $events->append($event);
        });

        return $events;
    }

    /**
     * The reason and device id of each recorded failure, and nothing for any
     * other recorded event.
     *
     * @param  \ArrayObject<int, object>  $events
     * @return list<array{0: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 1: ?string}>
     */
    private static function failures(\ArrayObject $events): array
    {
        $failures = [];

        foreach ($events as $event) {

            if (!$event instanceof AuthenticationFailed) {
                continue;
            }

            $failures[] = [$event->reason, $event->context->deviceId];
        }

        return $failures;
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $jwt = PackageAuth::jwt(self::GUARD);

        self::assertNotNull($jwt);

        return $jwt;
    }

    /**
     * A refresh token that takes the given path through the exchange, for a new
     * device of the identity.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  string  $path
     * @param  string  $rotationId
     * @return string
     */
    private function tokenForPath(StubPrincipal $identity, string $path, string $rotationId): string
    {
        $device = $this->seedDevice($identity, match ($path) {
            'current' => ['refresh_key' => RefreshTokenHasher::hash($rotationId), 'last_used_at' => $this->now],
            'grace'   => [
                'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor($rotationId)),
                'previous_refresh_key' => RefreshTokenHasher::hash($rotationId),
                'refresh_rotated_at'   => $this->now,
                'last_used_at'         => $this->now,
            ],
            default => ['refresh_key' => RefreshTokenHasher::hash('another-rotation-id')],
        });

        return $this->tokens()->issueRefreshToken($device, $rotationId, $identity);
    }
}
