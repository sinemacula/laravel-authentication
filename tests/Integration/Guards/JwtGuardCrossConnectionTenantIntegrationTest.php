<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\EagerLandlordTenantMember;
use Tests\Integration\Fixtures\LandlordTenant;
use Tests\Integration\Fixtures\LandlordTenantMember;
use Tests\Integration\Fixtures\LandlordTenantMembership;
use Tests\TestCase;

/**
 * Proves that a tenant kept on another connection than its members (a separate
 * landlord database) is read from that connection's writer too.
 *
 * Members and memberships live on the default split connection; tenants live on
 * the `landlord` split connection, whose replica lags behind its own primary. A
 * tenant deactivated on the landlord primary would still read as active if the
 * tenant were served by the landlord replica, whether the membership lazily
 * loads it during the activity check or the lookup eager-loads it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteConnection::class)]
#[CoversClass(ActivationPolicy::class)]
#[CoversClass(JwtGuard::class)]
final class JwtGuardCrossConnectionTenantIntegrationTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Plaintext password of the seeded member. */
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Create the member and membership tables on the default pair and the
     * tenant table on the landlord pair.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('landlord_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('landlord_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('landlord_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        }, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);
    }

    /**
     * Remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A membership that lazily loads its landlord tenant during the activity
     * check reads it from the landlord writer: once the tenant is deactivated
     * on the landlord primary, the member's bearer token is rejected although
     * the landlord replica still shows the tenant active.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsMemberWhoseLandlordTenantIsDeactivatedOnItsPrimary(): void
    {
        [$member, $membership, $tenant] = $this->seedMembership(new LandlordTenantMember);

        $request = $this->bearerRequest('lazy', $member, $membership);

        self::assertTrue($member->is($this->guardForRequest($request, 'lazy')->user()));

        $this->deactivate($tenant);

        self::assertNull($this->guardForRequest($request, 'lazy')->user());
    }

    /**
     * A membership whose hinted lookup eager-loads its landlord tenant reads it
     * from the landlord writer: once the tenant is deactivated on the landlord
     * primary, the member's bearer token is rejected although the landlord
     * replica still shows the tenant active.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsMemberWhoseEagerLoadedLandlordTenantIsDeactivatedOnItsPrimary(): void
    {
        [$member, $membership, $tenant] = $this->seedMembership(new EagerLandlordTenantMember);

        $request = $this->bearerRequest('eager', $member, $membership);

        self::assertTrue($member->is($this->guardForRequest($request, 'eager')->user()));

        $this->deactivate($tenant);

        self::assertNull($this->guardForRequest($request, 'eager')->user());
    }

    /**
     * Signing in resolves the default membership, whose landlord tenant is read
     * from the landlord writer: once the tenant is deactivated on the landlord
     * primary, the attempt fails although the landlord replica still shows the
     * tenant active.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsMemberWhoseLandlordTenantIsDeactivatedOnItsPrimary(): void
    {
        [, , $tenant] = $this->seedMembership(new LandlordTenantMember);

        $credentials = ['email' => 'member@example.test', 'password' => self::PASSWORD];

        self::assertTrue($this->guardForRequest(Request::create('/sign-in', 'POST'), 'lazy')->attempt($credentials));

        $this->deactivate($tenant);

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'), 'lazy');

        self::assertFalse($guard->attempt($credentials));
        self::assertFalse($guard->hasUser());
    }

    /**
     * Configure the lazy and eager member guards over the lagging split
     * connections.
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

        $this->configureLaggingReplica($config);
        $this->configureLaggingLandlordReplica($config);

        $config->set('auth.guards.lazy', ['driver' => 'jwt', 'provider' => 'lazy']);
        $config->set('auth.providers.lazy', ['driver' => 'model', 'model' => LandlordTenantMember::class]);

        $config->set('auth.guards.eager', ['driver' => 'jwt', 'provider' => 'eager']);
        $config->set('auth.providers.eager', ['driver' => 'model', 'model' => EagerLandlordTenantMember::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Create the devices table on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migrateDevicesOnPrimaryAndReplica();
    }

    /**
     * Write an active landlord tenant, the member and its membership, and copy
     * each row to its replica, so the replicas keep showing the tenant active
     * after the test deactivates it on the landlord primary.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Tests\Integration\Fixtures\EagerLandlordTenantMember|\Tests\Integration\Fixtures\LandlordTenantMember  $member
     * @return array{0: \Tests\Integration\Fixtures\EagerLandlordTenantMember|\Tests\Integration\Fixtures\LandlordTenantMember, 1: \Tests\Integration\Fixtures\LandlordTenantMembership, 2: \Tests\Integration\Fixtures\LandlordTenant}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMembership(EagerLandlordTenantMember|LandlordTenantMember $member): array
    {
        $tenant = new LandlordTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        $member->forceFill(['email' => 'member@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        $membership = new LandlordTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        $this->copyRowToReplica('landlord_tenants', $tenant->getKey(), self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);
        $this->copyRowToReplica('landlord_tenant_members', $member->getKey());
        $this->copyRowToReplica('landlord_tenant_memberships', $membership->getKey());

        return [$member, $membership, $tenant];
    }

    /**
     * Deactivate the tenant on the landlord primary only.
     *
     * @param  \Tests\Integration\Fixtures\LandlordTenant  $tenant
     * @return void
     */
    private function deactivate(LandlordTenant $tenant): void
    {
        LandlordTenant::query()->whereKey($tenant->getKey())->update(['is_active' => false]);

        self::assertFalse((bool) LandlordTenant::query()->useWritePdo()->whereKey($tenant->getKey())->value('is_active'));
        self::assertTrue((bool) LandlordTenant::query()->whereKey($tenant->getKey())->value('is_active'));
    }

    /**
     * Build a request carrying an access token for the member's membership,
     * issued by the named guard.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $member
     * @param  \Tests\Integration\Fixtures\LandlordTenantMembership  $membership
     * @return \Illuminate\Http\Request
     *
     * @throws \Random\RandomException
     */
    private function bearerRequest(string $guard, Identity $member, LandlordTenantMembership $membership): Request
    {
        $token = $this->authManager()->jwt($guard)->issueAccessToken($member, $membership, null);

        return Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);
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
     * Resolve a fresh JWT guard bound to the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForRequest(Request $request, string $name): JwtGuard
    {
        app()->instance('request', $request);

        $guard = $this->authManager()->guard($name);

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
