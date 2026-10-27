<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Tenant activity is enforced wherever principal activity is: a member of a
 * deactivated tenant cannot sign in, authenticate a bearer request, or refresh,
 * and the membership signs in again once the tenant is reactivated.
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
    /** @var string */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string */
    private const string ROTATION_ID = 'stored-rotation-id';

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
    }

    /**
     * Drop the fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
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
            'authenticatable_type' => ActivatableTenantMember::class,
            'authenticatable_id'   => (string) $member->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID, $membership);

        $tenant->forceFill(['is_active' => false])->save();

        $reasons = [];

        Event::listen(RefreshFailed::class, static function (RefreshFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull($this->freshGuard()->refresh($refreshToken));
        self::assertSame([RefreshFailureReason::TENANT_INACTIVE], $reasons);

        $fresh = Device::query()->findOrFail($device->getKey());

        assert($fresh instanceof Device);

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $fresh->getRefreshKey());
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
