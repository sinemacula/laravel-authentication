<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\EagerTenantMember;
use Tests\Integration\Fixtures\EagerTenantMembership;
use Tests\Integration\Fixtures\EagerTenantUser;
use Tests\TestCase;

/**
 * Proves that relations an authentication lookup eager-loads are read from the
 * write connection along with the row itself.
 *
 * Eloquent runs each eager load as a separate query that the write-PDO flag on
 * the lookup's own query does not reach. The fixtures eager-load the tenant on
 * every query, and the default connection is a read/write split whose replica
 * lags behind the primary, so a tenant deactivated on the primary would still
 * read as active if the eager load were served by the replica.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(ModelProvider::class)]
#[CoversClass(DefaultPrincipalResolver::class)]
final class JwtGuardEagerLoadWriteConnectionIntegrationTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Plaintext password of the seeded identities. */
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Create the tenant, member, membership, and user tables on the primary and
     * the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        $this->createOnPrimaryAndReplica('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('eager_tenant_users', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });
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
     * A membership found through the hinted `principals()->find()` lookup
     * eager-loads its tenant from the writer: once the tenant is deactivated on
     * the primary, the member's bearer token is rejected although the replica
     * still shows the tenant active.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsMemberWhoseEagerLoadedTenantIsDeactivatedOnThePrimary(): void
    {
        $tenant = $this->seedTenant();

        $member = new EagerTenantMember;
        $member->forceFill(['email' => 'member@example.test', 'password' => 'hashed'])->save();

        $membership = new EagerTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        $this->copyRowToReplica('activatable_tenant_members', $member->getKey());
        $this->copyRowToReplica('activatable_tenant_memberships', $membership->getKey());

        $token   = $this->authManager()->jwt('members')->issueAccessToken($member, $membership, null);
        $request = Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertTrue($member->is($this->guardForRequest($request, 'members')->user()));

        ActivatableTenant::query()->whereKey($tenant->getKey())->update(['is_active' => false]);

        self::assertNull($this->guardForRequest($request, 'members')->user());
    }

    /**
     * A 2D identity found by the model provider's `retrieveById()` eager-loads
     * its tenant from the writer: once the tenant is deactivated on the
     * primary, the user's bearer token is rejected although the replica still
     * shows the tenant active.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsUserWhoseEagerLoadedTenantIsDeactivatedOnThePrimary(): void
    {
        $user = $this->seedUser($this->seedTenant());

        $token   = $this->authManager()->jwt('users')->issueAccessToken($user, $user, null);
        $request = Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertTrue($user->is($this->guardForRequest($request, 'users')->user()));

        ActivatableTenant::query()->whereKey($user->tenant_id)->update(['is_active' => false]);

        self::assertNull($this->guardForRequest($request, 'users')->user());
    }

    /**
     * A 2D identity found by the model provider's `retrieveByCredentials()`
     * eager-loads its tenant from the writer: once the tenant is deactivated on
     * the primary, signing in fails although the replica still shows the tenant
     * active.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsUserWhoseEagerLoadedTenantIsDeactivatedOnThePrimary(): void
    {
        $user = $this->seedUser($this->seedTenant());

        $credentials = ['email' => 'user@example.test', 'password' => self::PASSWORD];

        self::assertTrue($this->guardForRequest(Request::create('/sign-in', 'POST'), 'users')->attempt($credentials));

        ActivatableTenant::query()->whereKey($user->tenant_id)->update(['is_active' => false]);

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'), 'users');

        self::assertFalse($guard->attempt($credentials));
        self::assertFalse($guard->hasUser());
    }

    /**
     * Configure the member and user guards over the lagging split connection.
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

        $config->set('auth.guards.members', [
            'driver'   => 'jwt',
            'provider' => 'members',
        ]);

        $config->set('auth.providers.members', [
            'driver' => 'model',
            'model'  => EagerTenantMember::class,
        ]);

        $config->set('auth.guards.users', [
            'driver'   => 'jwt',
            'provider' => 'users',
        ]);

        $config->set('auth.providers.users', [
            'driver' => 'model',
            'model'  => EagerTenantUser::class,
        ]);

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
     * Write an active tenant and copy it to the replica, so the replica keeps
     * showing it active after the test deactivates it on the primary.
     *
     * @return \Tests\Integration\Fixtures\ActivatableTenant
     */
    private function seedTenant(): ActivatableTenant
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        $this->copyRowToReplica('activatable_tenants', $tenant->getKey());

        return $tenant;
    }

    /**
     * Write a 2D user in the tenant and copy it to the replica.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @return \Tests\Integration\Fixtures\EagerTenantUser
     */
    private function seedUser(ActivatableTenant $tenant): EagerTenantUser
    {
        $user = new EagerTenantUser;
        $user->forceFill([
            'email'     => 'user@example.test',
            'password'  => app(Hasher::class)->make(self::PASSWORD),
            'tenant_id' => $tenant->getKey(),
        ])->save();

        $this->copyRowToReplica('eager_tenant_users', $user->getKey());

        return $user;
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
