<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity;

/**
 * Query-budget contracts for the main JwtGuard bearer-auth
 * success paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardQueryBudgetTest extends PerformanceContractTestCase
{
    private const string ACCESS_ONLY_GUARD = 'access_only';

    private const string DEVICE_GUARD = 'device_api';

    private const string THREE_D_GUARD = 'api_3d';

    private const string TENANT_AWARE_THREE_D_GUARD = 'tenant_api_3d';

    /**
     * Provision the fixture tables used by the three guard variants.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
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
     * Release the fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('tenant_aware_3d_principals');
        Schema::dropIfExists('tenant_aware_3d_tenants');
        Schema::dropIfExists('tenant_aware_3d_identities');
        Schema::dropIfExists('coexist_3d_principals');
        Schema::dropIfExists('coexist_3d_identities');
        Schema::dropIfExists('integration_identities');
        Schema::dropIfExists('access_only_identities');

        parent::tearDown();
    }

    /**
     * A 2D bearer token with no usable device hint should only rehydrate the
     * identity row.
     *
     * @return void
     */
    public function testAccessOnlyBearerPathUsesSingleReadAndNoWrites(): void
    {
        $identity = $this->seedAccessOnlyIdentity();
        $token = PackageAuth::jwt(self::ACCESS_ONLY_GUARD)->issueAccessToken($identity, $identity, null);

        $this->bindRequestWithBearer('/perf/access-only', $token);

        $guard = $this->freshJwtGuard(self::ACCESS_ONLY_GUARD);

        $result = $this->assertQueryBudget(1, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->principal();
            $guard->device();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * Once the shared bearer identity cache is warm, the access-only path
     * should avoid all SQL reads and writes on a fresh guard instance.
     *
     * @return void
     */
    public function testAccessOnlyBearerPathWithWarmIdentityCacheUsesZeroReadsAndNoWrites(): void
    {
        $identity = $this->seedAccessOnlyIdentity();
        $token = PackageAuth::jwt(self::ACCESS_ONLY_GUARD)->issueAccessToken($identity, $identity, null);

        config()->set('authentication.resolution_cache.jwt.identity_ttl_seconds', 15);

        $this->bindRequestWithBearer('/perf/access-only-cache-prime', $token);
        self::assertTrue($this->freshJwtGuard(self::ACCESS_ONLY_GUARD)->check());

        $this->bindRequestWithBearer('/perf/access-only-cache-warm', $token);

        $guard = $this->freshJwtGuard(self::ACCESS_ONLY_GUARD);

        $result = $this->assertQueryBudget(0, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->principal();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * A bearer token with a valid device hint and a fresh last-seen timestamp
     * should do the identity read plus the device read, but no update.
     *
     * @return void
     */
    public function testBearerPathWithDeviceHintAndFreshTimestampUsesTwoReadsAndNoWrites(): void
    {
        $identity = $this->seedIntegrationIdentity('device-fresh@example.test');

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => null,
            'last_logged_in_at'    => $this->now,
        ])->save();

        $token = PackageAuth::jwt(self::DEVICE_GUARD)->issueAccessToken($identity, $identity, $device);

        $this->bindRequestWithBearer('/perf/device-fresh', $token);

        $guard = $this->freshJwtGuard(self::DEVICE_GUARD);

        $result = $this->assertQueryBudget(2, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->device();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * With a warm shared identity cache, the device-bearing 2D path should do
     * only the live device lookup and no writes when the timestamp is fresh.
     *
     * @return void
     */
    public function testBearerPathWithDeviceHintAndWarmIdentityCacheUsesOneReadAndNoWrites(): void
    {
        $identity = $this->seedIntegrationIdentity('device-cache-fresh@example.test');

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => null,
            'last_logged_in_at'    => $this->now,
        ])->save();

        $token = PackageAuth::jwt(self::DEVICE_GUARD)->issueAccessToken($identity, $identity, $device);

        config()->set('authentication.resolution_cache.jwt.identity_ttl_seconds', 15);

        $this->bindRequestWithBearer('/perf/device-cache-prime', $token);
        self::assertTrue($this->freshJwtGuard(self::DEVICE_GUARD)->check());

        $this->bindRequestWithBearer('/perf/device-cache-warm', $token);

        $guard = $this->freshJwtGuard(self::DEVICE_GUARD);

        $result = $this->assertQueryBudget(1, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->device();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * A stale or missing last-seen timestamp should add exactly one write to
     * the mandatory identity + device reads.
     *
     * @return void
     */
    public function testBearerPathWithDeviceHintAndStaleTimestampUsesTwoReadsAndOneWrite(): void
    {
        $identity = $this->seedIntegrationIdentity('device-stale@example.test');

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => null,
            'last_logged_in_at'    => null,
        ])->save();

        $token = PackageAuth::jwt(self::DEVICE_GUARD)->issueAccessToken($identity, $identity, $device);

        $this->bindRequestWithBearer('/perf/device-stale', $token);

        $guard = $this->freshJwtGuard(self::DEVICE_GUARD);

        $result = $this->assertQueryBudget(2, 1, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->device();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * In 3D mode the bearer path should add one principal-resolution read on
     * top of the identity rehydration read.
     *
     * @return void
     */
    public function testThreeDimensionalBearerPathUsesTwoReadsAndNoWrites(): void
    {
        [$identity, $principal] = $this->seedThreeDimensionalFixtures();

        $token = PackageAuth::jwt(self::THREE_D_GUARD)->issueAccessToken($identity, $principal, null);

        $this->bindRequestWithBearer('/perf/3d', $token);

        $guard = $this->freshJwtGuard(self::THREE_D_GUARD);

        $result = $this->assertQueryBudget(2, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->principal();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * A tenant-aware 3D bearer token should keep tenant access in the same
     * principal-resolution read rather than triggering a third lookup.
     *
     * @return void
     */
    public function testThreeDimensionalBearerPathWithTenantAccessUsesTwoReadsAndNoWrites(): void
    {
        [$identity, $principal] = $this->seedTenantAwareThreeDimensionalFixtures();

        $token = PackageAuth::jwt(self::TENANT_AWARE_THREE_D_GUARD)->issueAccessToken($identity, $principal, null);

        $this->bindRequestWithBearer('/perf/3d-tenant-aware', $token);

        $guard = $this->freshJwtGuard(self::TENANT_AWARE_THREE_D_GUARD);

        $result = $this->assertQueryBudget(2, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->principal();
            $guard->tenant();
            $guard->type();
            $guard->principal()?->getIdentity();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * A tenant-aware bearer token for a secondary tenant should keep the
     * hinted-principal lookup to the same joined read budget as the primary
     * tenant path.
     *
     * @return void
     */
    public function testThreeDimensionalBearerPathWithSecondaryTenantHintUsesTwoReadsAndNoWrites(): void
    {
        [$identity, , $secondaryPrincipal] = $this->seedTenantAwareThreeDimensionalFixturesWithSecondaryTenant();

        $token = PackageAuth::jwt(self::TENANT_AWARE_THREE_D_GUARD)->issueAccessToken($identity, $secondaryPrincipal, null);

        $this->bindRequestWithBearer('/perf/3d-tenant-aware-secondary', $token);

        $guard = $this->freshJwtGuard(self::TENANT_AWARE_THREE_D_GUARD);

        $result = $this->assertQueryBudget(2, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->principal();
            $guard->tenant();
            $guard->type();
            $guard->principal()?->getIdentity();

            return $authenticated;
        });

        self::assertTrue($result);
        self::assertSame($secondaryPrincipal->getPrincipalIdentifier(), $guard->principal()?->getPrincipalIdentifier());
        self::assertSame('customer', $guard->type());
    }

    /**
     * With a warm identity cache, tenant-aware 3D bearer auth should only pay
     * the joined principal+tenant read.
     *
     * @return void
     */
    public function testThreeDimensionalBearerPathWithWarmIdentityCacheAndTenantAccessUsesOneReadAndNoWrites(): void
    {
        [$identity, $principal] = $this->seedTenantAwareThreeDimensionalFixtures('three-dimensional-warm@example.test');

        $token = PackageAuth::jwt(self::TENANT_AWARE_THREE_D_GUARD)->issueAccessToken($identity, $principal, null);

        config()->set('authentication.resolution_cache.jwt.identity_ttl_seconds', 15);

        $this->bindRequestWithBearer('/perf/3d-tenant-aware-prime', $token);
        self::assertTrue($this->freshJwtGuard(self::TENANT_AWARE_THREE_D_GUARD)->check());

        $this->bindRequestWithBearer('/perf/3d-tenant-aware-warm', $token);

        $guard = $this->freshJwtGuard(self::TENANT_AWARE_THREE_D_GUARD);

        $result = $this->assertQueryBudget(1, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->principal();
            $guard->tenant();
            $guard->type();
            $guard->principal()?->getIdentity();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * Configure the three JWT guards used by this test.
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

        $config->set('auth.defaults.guard', self::DEVICE_GUARD);

        $config->set('auth.guards.' . self::ACCESS_ONLY_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'access_only_identities',
        ]);

        $config->set('auth.guards.' . self::DEVICE_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'integration_identities',
        ]);

        $config->set('auth.guards.' . self::THREE_D_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'coexist_3d_identities',
        ]);

        $config->set('auth.guards.' . self::TENANT_AWARE_THREE_D_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'tenant_aware_3d_identities',
        ]);

        $config->set('auth.providers.access_only_identities', [
            'driver' => 'model',
            'model'  => PerformanceAccessOnlyIdentity::class,
        ]);

        $config->set('auth.providers.integration_identities', [
            'driver' => 'model',
            'model'  => IntegrationIdentity::class,
        ]);

        $config->set('auth.providers.coexist_3d_identities', [
            'driver' => 'model',
            'model'  => Coexist3dIdentity::class,
        ]);

        $config->set('auth.providers.tenant_aware_3d_identities', [
            'driver' => 'model',
            'model'  => TenantAware3dIdentity::class,
        ]);

        $config->set('cache.default', 'array');
        $config->set('authentication.device.last_seen_throttle_seconds', 60);
    }

    /**
     * Persist a 2D access-only identity.
     *
     * @return \Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity
     */
    private function seedAccessOnlyIdentity(): PerformanceAccessOnlyIdentity
    {
        $hasher = app(Hasher::class);

        $identity = new PerformanceAccessOnlyIdentity;
        $identity->email = 'access-only-performance@example.test';
        $identity->password = $hasher->make('correct horse battery staple');
        $identity->save();

        return $identity;
    }

    /**
     * Persist a 2D identity that also owns devices.
     *
     * @param  string  $email
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private function seedIntegrationIdentity(string $email): IntegrationIdentity
    {
        $hasher = app(Hasher::class);

        $identity = new IntegrationIdentity;
        $identity->email = $email;
        $identity->password = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Persist and return one 3D identity plus its active principal.
     *
     * @return array{0: \Tests\Integration\Fixtures\Coexist3dIdentity, 1: \Tests\Integration\Fixtures\Coexist3dPrincipal}
     */
    private function seedThreeDimensionalFixtures(): array
    {
        $hasher = app(Hasher::class);

        $identity = new Coexist3dIdentity;
        $identity->email = 'three-dimensional-performance@example.test';
        $identity->password = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        $principal = new Coexist3dPrincipal;
        $principal->identity_id = $identity->getKey();
        $principal->name = 'performance-actor';
        $principal->is_active = true;
        $principal->save();

        return [$identity, $principal];
    }

    /**
     * Persist and return one tenant-aware 3D identity plus its active
     * principal.
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\TenantAware3dIdentity, 1: \Tests\Integration\Fixtures\TenantAware3dPrincipal}
     */
    private function seedTenantAwareThreeDimensionalFixtures(
        string $email = 'tenant-aware-three-dimensional-performance@example.test',
    ): array
    {
        $hasher = app(Hasher::class);

        $identity = new TenantAware3dIdentity;
        $identity->email = $email;
        $identity->password = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        $tenant = new TenantAware3dTenant;
        $tenant->name = 'Performance Staff';
        $tenant->type = 'staff';
        $tenant->save();

        $principal = new TenantAware3dPrincipal;
        $principal->identity_id = $identity->getKey();
        $principal->tenant_id = $tenant->getKey();
        $principal->name = 'performance-staff-actor';
        $principal->is_active = true;
        $principal->save();

        return [$identity, $principal];
    }

    /**
     * Persist and return one tenant-aware 3D identity plus active principals
     * for two distinct tenant types.
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\TenantAware3dIdentity, 1: \Tests\Integration\Fixtures\TenantAware3dPrincipal, 2: \Tests\Integration\Fixtures\TenantAware3dPrincipal}
     */
    private function seedTenantAwareThreeDimensionalFixturesWithSecondaryTenant(
        string $email = 'tenant-aware-three-dimensional-secondary-performance@example.test',
    ): array {
        [$identity, $primaryPrincipal] = $this->seedTenantAwareThreeDimensionalFixtures($email);

        $secondaryTenant = new TenantAware3dTenant;
        $secondaryTenant->name = 'Performance Customer';
        $secondaryTenant->type = 'customer';
        $secondaryTenant->save();

        $secondaryPrincipal = new TenantAware3dPrincipal;
        $secondaryPrincipal->identity_id = $identity->getKey();
        $secondaryPrincipal->tenant_id = $secondaryTenant->getKey();
        $secondaryPrincipal->name = 'performance-customer-actor';
        $secondaryPrincipal->is_active = true;
        $secondaryPrincipal->save();

        return [$identity, $primaryPrincipal, $secondaryPrincipal];
    }
}
