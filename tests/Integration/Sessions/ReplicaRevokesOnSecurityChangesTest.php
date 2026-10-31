<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\TestCase;

/**
 * Proves a tenant's deactivation reads each principal's tenant from the write
 * connection: a principal the primary has just moved into a new tenant acts
 * within it, though the replica does not hold that tenant yet, and one whose
 * tenant, not opted into activation, was deleted acts within none. A
 * principal's deactivation reads its owner from the write connection too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevocations::class)]
#[CoversTrait(EndsSessions::class)]
final class ReplicaRevokesOnSecurityChangesTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /**
     * Create the identity, tenant and principal tables on the primary and the
     * replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('tenant_aware_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
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
     * The principal is accepted as acting within the new tenant, which only the
     * primary holds, and its sessions are ended for that tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalInATenantOnlyThePrimaryHoldsActsWithinIt(): void
    {
        $identity  = TenantAware3dIdentity::query()->create(['email' => 'member@example.test', 'password' => 'unused']);
        $tenant    = TenantAware3dTenant::query()->create(['name' => 'New', 'type' => 'team']);
        $principal = TenantAware3dPrincipal::query()->create(['identity_id' => $identity->getKey(), 'tenant_id' => $tenant->getKey(), 'name' => 'Member']);

        self::assertSame(0, TenantAware3dTenant::query()->count());

        $reported = [];

        Event::listen(SignedOutEverywhere::class, static function (SignedOutEverywhere $event) use (&$reported): void {
            $reported[] = $event;
        });

        self::assertSame(0, Auth::sessions('api')->tenantDeactivated($tenant, [$principal]));
        self::assertCount(1, $reported);
        self::assertSame($tenant, $reported[0]->context->tenant);
    }

    /**
     * A principal's owner that only the primary holds is read all the same, and
     * carried as the identity whose sessions ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsOwnerOnlyThePrimaryHoldsIsCarried(): void
    {
        $identity  = TenantAware3dIdentity::query()->create(['email' => 'member@example.test', 'password' => 'unused']);
        $tenant    = TenantAware3dTenant::query()->create(['name' => 'New', 'type' => 'team']);
        $principal = TenantAware3dPrincipal::query()->create(['identity_id' => $identity->getKey(), 'tenant_id' => $tenant->getKey(), 'name' => 'Member']);

        self::assertSame(0, TenantAware3dIdentity::query()->count());

        $reported = [];

        Event::listen(SignedOutEverywhere::class, static function (SignedOutEverywhere $event) use (&$reported): void {
            $reported[] = $event;
        });

        self::assertSame(0, Auth::sessions('api')->principalDeactivated($principal));
        self::assertCount(1, $reported);
        self::assertInstanceOf(TenantAware3dIdentity::class, $reported[0]->context->identity);
        self::assertSame($identity->getKey(), $reported[0]->context->identity->getKey());
    }

    /**
     * A tenant that does not opt into activation reads as no tenant once it is
     * deleted, so its deactivation can no longer tell that its principals act
     * within it and refuses them, writing nothing: the application calls
     * `tenantDeactivated()` before deleting such a tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeletedTenantThatDoesNotOptIntoActivationIsNoTenant(): void
    {
        $identity  = TenantAware3dIdentity::query()->create(['email' => 'member@example.test', 'password' => 'unused']);
        $tenant    = TenantAware3dTenant::query()->create(['name' => 'Gone', 'type' => 'team']);
        $principal = TenantAware3dPrincipal::query()->create(['identity_id' => $identity->getKey(), 'tenant_id' => $tenant->getKey(), 'name' => 'Member']);

        $tenant->delete();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('does not act within tenant ' . TenantAware3dTenant::class);

        Auth::sessions('api')->tenantDeactivated($tenant, [$principal]);
    }

    /**
     * Configure an `api` guard over a lagging read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('auth.providers.members', ['driver' => 'model', 'model' => TenantAware3dIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'members']);
        $config->set('auth.defaults.guard', 'api');

        $this->configureLaggingReplica($config);
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }
}
