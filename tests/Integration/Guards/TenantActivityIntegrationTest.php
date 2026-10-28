<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\DefaultTenantMembership;
use Tests\Integration\Fixtures\MorphTenantMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\StubFixedPrincipalResolver;

/**
 * Tenant activity is enforced wherever principal activity is: a member of a
 * deactivated tenant cannot sign in, authenticate a bearer request, or refresh,
 * and the membership signs in again once the tenant is reactivated. A tenant
 * that is soft-deleted or deleted blocks its members the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActivationPolicy::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class TenantActivityIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string */
    private const string ROTATION_ID = 'stored-rotation-id';

    /** @var bool Whether a query that runs now fails the test. */
    private bool $queriesForbidden = false;

    /**
     * Create the tenant, member, and membership tables.
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

        Schema::create('morph_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('tenant_type')->nullable();
            $blueprint->unsignedInteger('tenant_id')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->queriesForbidden = false;

        Schema::dropIfExists('morph_tenant_memberships');
        Schema::dropIfExists('activatable_tenant_memberships');
        Schema::dropIfExists('activatable_tenant_members');
        Schema::dropIfExists('activatable_tenants');

        parent::tearDown();
    }

    /**
     * A member of an active tenant signs in, and a member of the same tenant
     * cannot once the tenant is deactivated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsMemberOfInactiveTenant(): void
    {
        [$member, , $tenant] = $this->seedMembership();

        $credentials = ['email' => $member->email, 'password' => self::PASSWORD];

        self::assertTrue($this->freshGuard()->attempt($credentials));

        $tenant->forceFill(['is_active' => false])->save();

        $guard = $this->freshGuard();

        self::assertFalse($guard->attempt($credentials));
        self::assertNull($guard->identity());
    }

    /**
     * An access token issued while the tenant was active stops authenticating
     * as soon as the tenant is deactivated.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsMemberOfTenantDeactivatedAfterIssue(): void
    {
        [$member, $membership, $tenant] = $this->seedMembership();

        $token = $this->authManager()->jwt('api')->issueAccessToken($member, $membership, null);

        Route::middleware('auth:api')->get('/me', static function (): array {

            /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
            $manager = app('auth');

            return ['tenant' => $manager->tenant()?->getTenantIdentifier()];
        });

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me')
            ->assertOk()
            ->assertJson(['tenant' => $tenant->getKey()]);

        $tenant->forceFill(['is_active' => false])->save();

        $this->authManager();

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me')
            ->assertUnauthorized();
    }

    /**
     * Refresh for a member of a deactivated tenant fails with the
     * `tenant_inactive` reason and leaves the stored rotation untouched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsMemberOfInactiveTenantWithTenantInactiveReason(): void
    {
        [$member, $membership, $tenant] = $this->seedMembership();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => ActivatableTenantMember::class,
            'authenticatable_id'   => (string) $member->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID, $membership);

        $tenant->forceFill(['is_active' => false])->save();

        $reasons = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull($this->freshGuard()->refresh($refreshToken));
        self::assertSame([FailureReason::TENANT_INACTIVE], $reasons);

        $fresh = Device::query()->findOrFail($device->getKey());

        assert($fresh instanceof Device);

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $fresh->getRefreshKey());
    }

    /**
     * A member of a soft-deleted tenant cannot sign in: the membership names a
     * tenant the soft-delete scope hides, which is not the same as acting
     * within no tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsMemberOfSoftDeletedTenant(): void
    {
        [$member, , $tenant] = $this->seedMembership();

        $tenant->delete();

        $guard = $this->freshGuard();

        self::assertFalse($guard->attempt(['email' => $member->email, 'password' => self::PASSWORD]));
        self::assertNull($guard->identity());
    }

    /**
     * An access token issued before the tenant was soft-deleted stops
     * authenticating once it is.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsMemberOfSoftDeletedTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMembership();

        $token = $this->authManager()->jwt('api')->issueAccessToken($member, $membership, null);

        $tenant->delete();

        self::assertNull($this->bearerGuard($token)->user());
    }

    /**
     * An access token stops authenticating once its tenant row is deleted
     * outright and the membership's tenant key no longer names a row.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsMemberOfDeletedTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMembership();

        $token = $this->authManager()->jwt('api')->issueAccessToken($member, $membership, null);

        $tenant->forceDelete();

        self::assertNull($this->bearerGuard($token)->user());
    }

    /**
     * A membership loaded without its tenant key (a partial select) is reported
     * rather than read as acting within no tenant, so an inactive tenant cannot
     * be skipped by leaving the key out.
     *
     * @return void
     */
    public function testTenantCheckReportsAMembershipLoadedWithoutItsTenantKey(): void
    {
        [, $membership, $tenant] = $this->seedMembership();

        $tenant->forceFill(['is_active' => false])->save();

        $full = ActivatableTenantMembership::query()->find($membership->getKey());

        self::assertInstanceOf(ActivatableTenantMembership::class, $full);
        self::assertFalse(ActivationPolicy::isTenantActive($full));

        $partial = ActivatableTenantMembership::query()->select(['id', 'identity_id'])->find($membership->getKey());

        self::assertInstanceOf(ActivatableTenantMembership::class, $partial);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `tenant_id` attribute is not loaded');

        ActivationPolicy::isTenantActive($partial);
    }

    /**
     * A membership whose tenant is a polymorphic relation, loaded without its
     * type column, is reported rather than read as acting within no tenant:
     * without the type Eloquent builds the relation against the membership's
     * own model, so an inactive tenant would otherwise be skipped. The report
     * comes before any lazy load, which PostgreSQL and MySQL reject for a
     * relation built without its type.
     *
     * @return void
     */
    public function testTenantCheckReportsAMorphMembershipLoadedWithoutItsTenantType(): void
    {
        $membership = $this->seedMorphMembership();

        $full = MorphTenantMembership::query()->find($membership->getKey());

        self::assertInstanceOf(MorphTenantMembership::class, $full);
        self::assertFalse(ActivationPolicy::isTenantActive($full));

        $partial = MorphTenantMembership::query()->select(['id', 'identity_id', 'tenant_id'])->find($membership->getKey());

        self::assertInstanceOf(MorphTenantMembership::class, $partial);

        $this->failOnAnyQuery();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `tenant_type` attribute is not loaded');

        ActivationPolicy::isTenantActive($partial);
    }

    /**
     * A polymorphic tenant whose key is set but whose type is empty cannot be
     * loaded, so the membership is rejected rather than read as acting within
     * no tenant, without the lazy load PostgreSQL and MySQL reject for an empty
     * type.
     *
     * @return void
     */
    public function testTenantCheckRejectsAMorphMembershipWhoseTenantTypeIsEmpty(): void
    {
        $membership = $this->seedMorphMembership();

        MorphTenantMembership::query()->whereKey($membership->getKey())->update(['tenant_type' => null]);

        $stored = MorphTenantMembership::query()->find($membership->getKey());

        self::assertInstanceOf(MorphTenantMembership::class, $stored);

        $this->failOnAnyQuery();

        self::assertFalse(ActivationPolicy::isTenantActive($stored));
    }

    /**
     * A tenant relation declared with `withDefault()` does not turn a deleted
     * tenant into a present, active one: the unsaved placeholder it returns
     * reads as a tenant that cannot be loaded.
     *
     * @return void
     */
    public function testTenantCheckRejectsAWithDefaultMembershipOfASoftDeletedTenant(): void
    {
        [, $membership, $tenant] = $this->seedMembership();

        $active = DefaultTenantMembership::query()->find($membership->getKey());

        self::assertInstanceOf(DefaultTenantMembership::class, $active);
        self::assertTrue(ActivationPolicy::isTenantActive($active));

        $tenant->delete();

        $orphaned = DefaultTenantMembership::query()->find($membership->getKey());

        self::assertInstanceOf(DefaultTenantMembership::class, $orphaned);
        self::assertFalse(ActivationPolicy::isTenantActive($orphaned));
    }

    /**
     * Signing in with a resolver that loads the membership without its tenant
     * key reports the misconfiguration instead of signing in as if the member
     * acted within no tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptReportsAMembershipLoadedWithoutItsTenantKey(): void
    {
        [$member, $membership] = $this->seedMembership();

        $partial = ActivatableTenantMembership::query()->select(['id', 'identity_id'])->findOrFail($membership->getKey());

        $guard = $this->freshGuard()->setPrincipalResolver(new StubFixedPrincipalResolver($partial));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `tenant_id` attribute is not loaded');

        $guard->attempt(['email' => $member->email, 'password' => self::PASSWORD]);
    }

    /**
     * A bearer request whose resolver loads a polymorphic membership without
     * its tenant type reports the misconfiguration instead of authenticating a
     * member of an inactive tenant.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerReportsAMorphMembershipLoadedWithoutItsTenantType(): void
    {
        $membership = $this->seedMorphMembership();
        $member     = ActivatableTenantMember::query()->findOrFail($membership->identity_id);

        $token   = $this->authManager()->jwt('api')->issueAccessToken($member, $membership, null);
        $partial = MorphTenantMembership::query()->select(['id', 'identity_id', 'tenant_id'])->findOrFail($membership->getKey());

        $guard = $this->bearerGuard($token)->setPrincipalResolver(new StubFixedPrincipalResolver($partial));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `tenant_type` attribute is not loaded');

        $guard->user();
    }

    /**
     * Refresh for a polymorphic membership whose tenant key is set but whose
     * type is empty fails with `tenant_inactive` and leaves the stored rotation
     * untouched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsAMorphMembershipWhoseTenantTypeIsEmptyWithTenantInactiveReason(): void
    {
        $membership = $this->seedMorphMembership();
        $member     = ActivatableTenantMember::query()->findOrFail($membership->identity_id);
        $device     = $this->seedDevice($member);

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID, $membership);

        MorphTenantMembership::query()->whereKey($membership->getKey())->update(['tenant_type' => '']);

        $reasons = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        $guard = $this->freshGuard()->setPrincipalResolver(new StubFixedPrincipalResolver(MorphTenantMembership::query()->findOrFail($membership->getKey())));

        self::assertNull($guard->refresh($refreshToken));
        self::assertSame([FailureReason::TENANT_INACTIVE], $reasons);

        $fresh = Device::query()->findOrFail($device->getKey());

        assert($fresh instanceof Device);

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $fresh->getRefreshKey());
    }

    /**
     * Signing in as a member whose `withDefault()` membership names a
     * soft-deleted tenant fails: the placeholder the relation returns is not a
     * present, active tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsAWithDefaultMembershipOfASoftDeletedTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMembership();

        $tenant->delete();

        $orphaned = DefaultTenantMembership::query()->findOrFail($membership->getKey());
        $guard    = $this->freshGuard()->setPrincipalResolver(new StubFixedPrincipalResolver($orphaned));

        self::assertFalse($guard->attempt(['email' => $member->email, 'password' => self::PASSWORD]));
        self::assertNull($guard->identity());
    }

    /**
     * Refresh for a member of a soft-deleted tenant fails with the
     * `tenant_inactive` reason.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsMemberOfSoftDeletedTenantWithTenantInactiveReason(): void
    {
        [$member, $membership, $tenant] = $this->seedMembership();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => ActivatableTenantMember::class,
            'authenticatable_id'   => (string) $member->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID, $membership);

        $tenant->delete();

        $reasons = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull($this->freshGuard()->refresh($refreshToken));
        self::assertSame([FailureReason::TENANT_INACTIVE], $reasons);
    }

    /**
     * Configure the JWT guard against the member provider.
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
            'provider' => 'members',
        ]);

        $config->set('auth.providers.members', [
            'driver' => 'model',
            'model'  => ActivatableTenantMember::class,
        ]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist a member with one membership in an active tenant.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMember, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenant}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMembership(): array
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        $member = new ActivatableTenantMember;
        $member->forceFill([
            'email'    => 'member@example.test',
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ])->save();

        $membership = new ActivatableTenantMembership;
        $membership->forceFill([
            'identity_id' => $member->getKey(),
            'tenant_id'   => $tenant->getKey(),
        ])->save();

        return [$member, $membership, $tenant];
    }

    /**
     * Persist a member with a polymorphic membership in an inactive tenant.
     *
     * @return \Tests\Integration\Fixtures\MorphTenantMembership
     */
    private function seedMorphMembership(): MorphTenantMembership
    {
        [$member, , $tenant] = $this->seedMembership();

        $tenant->forceFill(['is_active' => false])->save();

        $membership = new MorphTenantMembership;
        $membership->forceFill([
            'identity_id' => $member->getKey(),
            'tenant_type' => ActivatableTenant::class,
            'tenant_id'   => $tenant->getKey(),
        ])->save();

        return $membership;
    }

    /**
     * Persist a device holding the stored rotation for the member.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMember  $member
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(ActivatableTenantMember $member): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => ActivatableTenantMember::class,
            'authenticatable_id'   => (string) $member->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return $device;
    }

    /**
     * Fail the test as soon as any query runs, until tear-down.
     *
     * @return void
     */
    private function failOnAnyQuery(): void
    {
        $this->queriesForbidden = true;

        DB::listen(function (QueryExecuted $query): void {

            if (!$this->queriesForbidden) {
                return;
            }

            self::fail('Expected no query, but ran: ' . $query->sql);
        });
    }

    /**
     * Resolve the package auth manager with no cached guards.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function authManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }

    /**
     * Resolve a fresh `api` JWT guard against a request carrying the bearer
     * token.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearerGuard(#[\SensitiveParameter] string $token): JwtGuard
    {
        app()->instance('request', Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }

    /**
     * Resolve a fresh `api` JWT guard against a fresh request.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function freshGuard(): JwtGuard
    {
        app()->instance('request', Request::create('/sign-in', 'POST'));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
