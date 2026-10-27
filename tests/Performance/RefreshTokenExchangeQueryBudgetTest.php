<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Query-budget contracts for the refresh-token exchange hot paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
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
     * Refresh success should do the device lookup and authenticatable
     * hydration, then one CAS write. The timestamp write is suppressed here by
     * seeding `last_used_at` inside the throttle window.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshSuccessUsesTwoReadsAndOneWrite(): void
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

        $result = $this->assertQueryBudget(2, 1, static fn () => $guard->refresh($token));

        self::assertNotNull($result);
    }

    /**
     * Unknown-device refresh failures should stop at the first device lookup.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUnknownDeviceRefreshFailureUsesOneReadAndNoWrites(): void
    {
        $missingDevice = new Device;
        $missingDevice->forceFill([...self::liveSession(), 'id' => '00000000-0000-0000-0000-000000000000']);

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($missingDevice, 'missing-device-rotation');

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(1, 0, static fn () => $guard->refresh($token));

        self::assertNull($result);
    }

    /**
     * A device id that cannot be a key of the device model is rejected before
     * the device lookup, so the failure costs no query at all.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMalformedDeviceIdRefreshFailureUsesNoQueries(): void
    {
        $malformedDevice = new Device;
        $malformedDevice->forceFill([...self::liveSession(), 'id' => 'not-a-uuid']);

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($malformedDevice, 'malformed-device-rotation');

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(0, 0, static fn () => $guard->refresh($token));

        self::assertNull($result);
    }

    /**
     * A replayed refresh token is judged from the device row alone, before the
     * owner is loaded, and costs the device read plus the one guarded
     * revocation write.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReplayRevocationUsesOneReadAndOneWrite(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, ['refresh_key' => RefreshTokenHasher::hash('stored-rotation-id')]);

        $token = $this->tokens()->issueRefreshToken($device, 'replayed-rotation-id');
        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertNull($this->assertQueryBudget(1, 1, static fn () => $guard->refresh($token)));
        self::assertSame('rotation_reuse', Device::query()->whereKey($device->getKey())->firstOrFail()->getRevokedReason());
    }

    /**
     * A grace retry is answered from the device row and the owner with no write
     * at all: the current credential is re-issued, not rotated again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGraceRetryUsesTwoReadsAndNoWrites(): void
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

        self::assertNotNull($this->assertQueryBudget(2, 0, static fn () => $guard->refresh($token)));
    }

    /**
     * A refresh that loses its swap to a parallel refresh with the same token
     * pays the device and owner reads, the missed swap, and one locking re-read
     * of the device, then succeeds as a grace retry.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLostRotationResolvedAsAGraceRetryUsesThreeReadsAndOneWrite(): void
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

        self::assertNotNull($this->assertQueryBudget(3, 1, static fn () => $guard->refresh($token)));
    }

    /**
     * A refresh for a device that holds no refresh credential stops at the
     * device lookup and writes nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMissingRefreshCredentialUsesOneReadAndNoWrites(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity, ['refresh_key' => null]);

        $token = $this->tokens()->issueRefreshToken($device, 'any-rotation-id');
        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertNull($this->assertQueryBudget(1, 0, static fn () => $guard->refresh($token)));
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
     * lookup: the deadlines are read from the loaded row, and nothing is
     * written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEndedSessionRefreshFailureUsesOneReadAndNoWrites(): void
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

        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertNull($this->assertQueryBudget(1, 0, static fn () => $guard->refresh($token)));
    }

    /**
     * Tenant-aware 3D refresh success should pay exactly the device read, the
     * authenticatable read, the joined principal+tenant read, and one rotation
     * write.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPathWithTenantAccessUsesThreeReadsAndOneWrite(): void
    {
        [$identity, $principal] = $this->seedTenantAwareThreeDimensionalFixtures();
        $rotationId             = 'refresh-tenant-aware-success';

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, $rotationId, $principal);
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(3, 1, static function () use ($guard, $token): ?RefreshResult {
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
     * same device + identity + joined principal read budget as the primary
     * tenant path.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPathWithSecondaryTenantHintUsesThreeReadsAndOneWrite(): void
    {
        [$identity, , $secondaryPrincipal] = $this->seedTenantAwareThreeDimensionalFixturesWithSecondaryTenant();
        $rotationId                        = 'refresh-tenant-aware-secondary-success';

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, $rotationId, $secondaryPrincipal);
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(3, 1, static function () use ($guard, $token): ?RefreshResult {
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
     * A failure on the 3D pid path must still stop before the rotation write.
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
            ...self::liveSession(),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, $rotationId, $principal);
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(3, 0, static function () use ($guard, $token): ?RefreshResult {
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
