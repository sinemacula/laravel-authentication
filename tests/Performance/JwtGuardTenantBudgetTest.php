<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\EagerTenantMember;
use Tests\Integration\Fixtures\EagerTenantMembership;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\Integration\Fixtures\UncheckedTenantUser;

/**
 * Query-budget contracts for the tenant activity check on the bearer and
 * refresh paths.
 *
 * The check reads the tenant the principal acts within on every request. A
 * tenant the principal resolver eager-loads costs that eager load; one it does
 * not costs a lazy load, whether or not the tenant opts into activation,
 * because the check learns whether it opts in from the loaded model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActivationPolicy::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class JwtGuardTenantBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithDevices;

    /** @var string Plaintext rotation id stored on the seeded devices. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /**
     * Provision the tenant fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        Schema::create('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        Schema::create('unchecked_tenant_users', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });
    }

    /**
     * Release the tenant fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('unchecked_tenant_users');
        Schema::dropIfExists('tenant_aware_3d_tenants');
        Schema::dropIfExists('activatable_tenant_memberships');
        Schema::dropIfExists('activatable_tenant_members');
        Schema::dropIfExists('activatable_tenants');

        parent::tearDown();
    }

    /**
     * Rows of `[guard]`: a member of a tenant that opts into activation, with
     * the tenant eager-loaded with the principal or lazily loaded by the check.
     * Eloquent runs an eager load as a query of its own, so both cost the same.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOptedInTenantGuards(): iterable
    {
        yield from [
            'eager-loaded tenant'  => ['eager_members'],
            'lazily loaded tenant' => ['members'],
        ];
    }

    /**
     * A bearer request for a member of a tenant that opts in reads the
     * identity, the principal and the tenant once each while authenticating,
     * and writes nothing. The tenant accessor then reuses the tenant the check
     * loaded, so the check cannot leave that read to the accessor.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideOptedInTenantGuards')]
    public function testBearerForAMemberOfAnOptedInTenantUsesThreeReadsAndNoWrites(string $guard): void
    {
        [$member, $membership, $tenant] = $this->seedMembership($guard);

        $this->bindRequestWithBearer('/perf/tenant', $this->tokensFor($guard)->issueAccessToken($member, $membership, null));

        $resolved = $this->freshJwtGuard($guard);

        self::assertTrue($this->assertQueryBudget(3, 0, static fn (): bool => $resolved->check()));
        self::assertSame($tenant->getKey(), $this->assertQueryBudget(0, 0, static fn (): mixed => $resolved->tenant()?->getTenantIdentifier()));
    }

    /**
     * A bearer request for a member of an inactive tenant spends the same three
     * reads to reach the tenant check, is rejected, and writes nothing.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideOptedInTenantGuards')]
    public function testBearerForAMemberOfAnInactiveTenantIsRejectedInThreeReadsAndNoWrites(string $guard): void
    {
        [$member, $membership] = $this->seedMembership($guard, false);

        $this->bindRequestWithBearer('/perf/tenant', $this->tokensFor($guard)->issueAccessToken($member, $membership, null));

        $resolved = $this->freshJwtGuard($guard);

        self::assertFalse($this->assertQueryBudget(3, 0, static fn (): bool => $resolved->check()));
        self::assertNull($resolved->tenant());
    }

    /**
     * A refresh for a member of a tenant that opts in reads its refresh limits,
     * the device, the owner, the principal and the tenant once each, and writes
     * only the rotation.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideOptedInTenantGuards')]
    public function testRefreshForAMemberOfAnOptedInTenantUsesFiveReadsAndOneWrite(string $guard): void
    {
        [$member, $membership] = $this->seedMembership($guard);

        $device = $this->seedDevice($member, $guard);
        $token  = $this->tokensFor($guard)->issueRefreshToken($device, self::ROTATION_ID, $membership);

        app()->instance('request', Request::create('/refresh', 'POST'));

        $resolved = $this->freshJwtGuard($guard);

        self::assertInstanceOf(RefreshResult::class, $this->assertQueryBudget(5, 1, static fn (): ?RefreshResult => $resolved->refresh($token)));
    }

    /**
     * A refresh for a member of an inactive tenant spends the same five reads
     * to reach the tenant check, is rejected, and leaves the rotation alone.
     * Its only writes count the failure against the device and the IP address:
     * on a fresh window, an update that changes nothing and the insert that
     * creates the counter, for each.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideOptedInTenantGuards')]
    public function testRefreshForAMemberOfAnInactiveTenantIsRejectedInFiveReadsAndCountsTheFailure(string $guard): void
    {
        [$member, $membership] = $this->seedMembership($guard, false);

        $device = $this->seedDevice($member, $guard);
        $token  = $this->tokensFor($guard)->issueRefreshToken($device, self::ROTATION_ID, $membership);

        app()->instance('request', Request::create('/refresh', 'POST'));

        $resolved = $this->freshJwtGuard($guard);

        self::assertNull($this->assertQueryBudget(5, 4, static fn (): ?RefreshResult => $resolved->refresh($token)));
    }

    /**
     * A bearer request for a 2D user whose tenant does not opt into activation
     * still loads that tenant for the check: one read on top of the identity.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerForAUserOfALazilyLoadedTenantThatDoesNotOptInUsesTwoReadsAndNoWrites(): void
    {
        $tenant = new TenantAware3dTenant;
        $tenant->forceFill(['name' => 'Tenant', 'type' => 'customer'])->save();

        $user = new UncheckedTenantUser;
        $user->forceFill(['email' => 'unchecked@example.test', 'password' => 'irrelevant', 'tenant_id' => $tenant->getKey()])->save();

        $this->bindRequestWithBearer('/perf/unchecked-tenant', $this->tokensFor('unchecked')->issueAccessToken($user, $user, null));

        $guard = $this->freshJwtGuard('unchecked');

        self::assertTrue($this->assertQueryBudget(2, 0, static fn (): bool => $guard->check()));
    }

    /**
     * Configure guards for eager-loaded and lazily loaded opted-in tenants and
     * for a tenant that does not opt in.
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

        $providers = [
            'eager_members' => EagerTenantMember::class,
            'members'       => ActivatableTenantMember::class,
            'unchecked'     => UncheckedTenantUser::class,
        ];

        foreach ($providers as $name => $model) {
            $config->set('auth.guards.' . $name, ['driver' => 'jwt', 'provider' => $name]);
            $config->set('auth.providers.' . $name, ['driver' => 'model', 'model' => $model]);
        }
    }

    /**
     * Persist a member with one membership in a tenant that opts in, through
     * the models the guard uses.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $guard
     * @param  bool  $tenantActive
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Principal, 2: \Tests\Integration\Fixtures\ActivatableTenant}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMembership(string $guard, bool $tenantActive = true): array
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => $tenantActive])->save();

        [$memberClass, $membershipClass] = $guard === 'eager_members'
            ? [EagerTenantMember::class, EagerTenantMembership::class]
            : [ActivatableTenantMember::class, ActivatableTenantMembership::class];

        $member = new $memberClass;
        $member->forceFill(['email' => 'member@example.test', 'password' => 'irrelevant'])->save();

        $membership = new $membershipClass;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        return [$member, $membership, $tenant];
    }

    /**
     * Persist a device of the guard for the member holding the stored rotation.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $member
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(Identity&Model $member, string $guard): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession($guard),
            'authenticatable_type' => $member::class,
            'authenticatable_id'   => (string) $member->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
            'last_used_at'         => $this->now,
        ])->save();

        return $device;
    }

    /**
     * Resolve the token service of a guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokensFor(string $guard): JwtTokenService
    {
        $tokens = PackageAuth::jwt($guard);

        self::assertNotNull($tokens);

        return $tokens;
    }
}
