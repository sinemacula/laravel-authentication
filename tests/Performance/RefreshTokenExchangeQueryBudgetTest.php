<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
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
    /** @var string Guard name for standard refresh tests. */
    private const string GUARD = 'api';

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
     * seeding `last_logged_in_at` inside the throttle window.
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
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_logged_in_at'    => $this->now,
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
        $missingDevice->forceFill(['id' => '00000000-0000-0000-0000-000000000000']);

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($missingDevice, 'missing-device-rotation');

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(1, 0, static fn () => $guard->refresh($token));

        self::assertNull($result);
    }

    /**
     * Rotation-mismatch refresh failures should do the device lookup but avoid
     * authenticatable hydration and writes.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRotationMismatchRefreshFailureUsesOneReadAndNoWrites(): void
    {
        $identity = $this->seedIdentity();

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash('stored-rotation-id'),
        ])->save();

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($device, 'tampered-rotation-id');
        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(1, 0, static fn () => $guard->refresh($token));

        self::assertNull($result);
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
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'tenant-aware-ios',
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_logged_in_at'    => $this->now,
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
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'tenant-aware-ios-secondary',
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_logged_in_at'    => $this->now,
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
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'tenant-aware-ios-failure',
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_logged_in_at'    => $this->now,
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

        $config->set('authentication.device.last_seen_throttle_seconds', 60);
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
}
