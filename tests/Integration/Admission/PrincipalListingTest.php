<?php

declare(strict_types = 1);

namespace Tests\Integration\Admission;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\PrincipalListing;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\LandlordTenant;
use Tests\Integration\Fixtures\LandlordTenantMember;
use Tests\Integration\Fixtures\LandlordTenantMembership;
use Tests\TestCase;

/**
 * Integration tests for reading listed principals' tenants on the writer of the
 * tenants' own connection: the members and memberships live on the default
 * split, the tenants on the `landlord` split, and both replicas lag behind
 * their primaries, so a tenant deactivated on the landlord primary would still
 * read as active if the tenants loaded together were served by the landlord
 * replica.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalListing::class)]
final class PrincipalListingTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Guard over the members. */
    private const string GUARD = 'members';

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
     * A listed membership whose landlord tenant was deactivated on the landlord
     * primary is refused as `tenant_inactive` and no longer offered, though the
     * landlord replica still shows the tenant active; the other membership is
     * offered, holding its tenant as the primary has it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantsAreReadOnTheirOwnPrimary(): void
    {
        $member = new LandlordTenantMember;
        $member->forceFill(['email' => 'member@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        $this->copyRowToReplica('landlord_tenant_members', $member->getKey());

        [$kept, $keptTenant] = $this->seedMembership($member, 'Kept');
        [, $lostTenant]      = $this->seedMembership($member, 'Lost');

        LandlordTenant::query()->whereKey($lostTenant->getKey())->update(['is_active' => false]);

        self::assertFalse((bool) LandlordTenant::query()->useWritePdo()->whereKey($lostTenant->getKey())->value('is_active'));
        self::assertTrue((bool) LandlordTenant::query()->whereKey($lostTenant->getKey())->value('is_active'));

        $listing    = PrincipalListing::of($member);
        $candidates = array_values(array_filter($listing->candidates, static fn (mixed $candidate): bool => $candidate instanceof Principal));

        self::assertSame([null, FailureReason::TENANT_INACTIVE], $listing->refusals(self::GUARD, $candidates));

        $offered = Auth::sessions(self::GUARD)->principals($member);

        self::assertCount(1, $offered);
        self::assertTrue($kept->is($offered[0]));
        self::assertTrue($keptTenant->is($offered[0]->getTenant()));
    }

    /**
     * Configure the member guard over the lagging split connections.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $this->configureLaggingReplica($config);
        $this->configureLaggingLandlordReplica($config);

        $config->set('auth.providers.' . self::GUARD, ['driver' => 'model', 'model' => LandlordTenantMember::class]);
        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => self::GUARD, 'application' => ['methods' => ['password']]]);
    }

    /**
     * Create the package tables on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Write an active landlord tenant and a membership of the member in it, and
     * copy each row to its replica.
     *
     * @param  \Tests\Integration\Fixtures\LandlordTenantMember  $member
     * @param  string  $name
     * @return array{0: \Tests\Integration\Fixtures\LandlordTenantMembership, 1: \Tests\Integration\Fixtures\LandlordTenant}
     */
    private function seedMembership(LandlordTenantMember $member, string $name): array
    {
        $tenant = new LandlordTenant;
        $tenant->forceFill(['name' => $name, 'is_active' => true])->save();

        $membership = new LandlordTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        $this->copyRowToReplica('landlord_tenants', $tenant->getKey(), self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);
        $this->copyRowToReplica('landlord_tenant_memberships', $membership->getKey());

        return [$membership, $tenant];
    }
}
