<?php

declare(strict_types = 1);

namespace Tests\Integration\Applications;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\PrincipalAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\LandlordPrincipal;
use Tests\Integration\Fixtures\LandlordPrincipalMember;
use Tests\TestCase;

/**
 * Proves the principals offered to an identity, and the one principal looked up
 * by its identifier, are read and admitted with `ApplicationAccess` on the
 * principal's write connection, also when the principals live on another
 * connection than the identity: the identity is on the lagging default split,
 * its principals and their grants on the lagging `landlord` split, so an answer
 * read from the landlord replica would still hold a withdrawn grant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingEvaluation::class)]
#[CoversClass(PrincipalAdmission::class)]
final class ReplicaChoicesAcrossConnectionsTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessions;

    /** @var string Guard over the members whose principals live on the landlord connection. */
    private const string GUARD = 'landlord_members';

    /** @var string Table of the principals the application admits. */
    private const string GRANTS = 'principal_grants';

    /**
     * Create the member table on the default primary and replica, the principal
     * and grant tables on the landlord primary and replica, and bind the access
     * that reads the grants.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('landlord_principal_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica(self::GRANTS, static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('principal_id');
        }, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);

        $this->createOnPrimaryAndReplica('landlord_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->timestamps();
        }, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);

        app()->instance(ApplicationAccess::class, $this->access());
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
     * A principal whose grant the landlord primary has withdrawn is no longer
     * offered, with or without an identifier type, though the landlord replica
     * still holds the grant; the other is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsAreAdmittedOnThePrincipalsPrimary(): void
    {
        $member = LandlordPrincipalMember::query()->create(['email' => 'member@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $first  = LandlordPrincipal::query()->create(['identity_id' => $member->id]);
        $second = LandlordPrincipal::query()->create(['identity_id' => $member->id]);
        $grant  = $this->grant($first);

        $this->grant($second);

        self::assertSame([$first->id, $second->id], $this->offered($member, null));
        self::assertSame([$first->id, $second->id], $this->offered($member, 'email'));

        $this->withdrawOnThePrimary($grant);

        self::assertSame([$second->id], $this->offered($member, null));
        self::assertSame([$second->id], $this->offered($member, 'email'));
    }

    /**
     * One principal is found as the landlord primary holds and admits it: the
     * principals exist only on the landlord primary, and the one whose grant
     * the primary has withdrawn is no longer found, with or without an
     * identifier type, though the landlord replica still holds the grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnePrincipalIsFoundAndAdmittedOnThePrincipalsPrimary(): void
    {
        $member = LandlordPrincipalMember::query()->create(['email' => 'member@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $first  = LandlordPrincipal::query()->create(['identity_id' => $member->id]);
        $second = LandlordPrincipal::query()->create(['identity_id' => $member->id]);
        $grant  = $this->grant($first);

        $this->grant($second);

        self::assertFalse(DB::connection(self::LANDLORD_REPLICA_CONNECTION)->table('landlord_principals')->exists());
        self::assertSame($first->id, $this->sessions(self::GUARD)->principal($member, $first->id)?->getPrincipalIdentifier());
        self::assertSame($first->id, $this->sessions(self::GUARD)->principal($member, $first->id, 'email')?->getPrincipalIdentifier());

        $this->withdrawOnThePrimary($grant);

        self::assertNull($this->sessions(self::GUARD)->principal($member, $first->id));
        self::assertNull($this->sessions(self::GUARD)->principal($member, $first->id, 'email'));
        self::assertSame($second->id, $this->sessions(self::GUARD)->principal($member, $second->id)?->getPrincipalIdentifier());
    }

    /**
     * Configure a guard over the members, the lagging default split and the
     * lagging landlord split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.landlord_members', ['driver' => 'model', 'model' => LandlordPrincipalMember::class]);
        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'landlord_members', 'application' => ['methods' => ['password']]]);

        $this->configureLaggingReplica($config);
        $this->configureLaggingLandlordReplica($config);
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

    /**
     * The keys of the principals the guard offers the member, with the
     * identifier type.
     *
     * @param  \Tests\Integration\Fixtures\LandlordPrincipalMember  $member
     * @param  ?string  $identifierType
     * @return list<mixed>
     *
     * @throws \Throwable
     */
    private function offered(LandlordPrincipalMember $member, ?string $identifierType): array
    {
        return array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $this->sessions(self::GUARD)->principals($member, $identifierType));
    }

    /**
     * Grant the principal the application, on the landlord primary only.
     *
     * @param  \Tests\Integration\Fixtures\LandlordPrincipal  $principal
     * @return int
     */
    private function grant(LandlordPrincipal $principal): int
    {
        return DB::connection(self::LANDLORD_CONNECTION)->table(self::GRANTS)->insertGetId(['principal_id' => $principal->id]);
    }

    /**
     * Copy the grant to the landlord replica, then delete it on the landlord
     * primary, as a replica that lags behind the withdrawal would still hold
     * it.
     *
     * @param  int  $id
     * @return void
     */
    private function withdrawOnThePrimary(int $id): void
    {
        $this->copyRowToReplica(self::GRANTS, $id, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);

        DB::connection(self::LANDLORD_CONNECTION)->table(self::GRANTS)->where('id', $id)->delete();

        self::assertFalse(DB::connection(self::LANDLORD_PRIMARY_CONNECTION)->table(self::GRANTS)->where('id', $id)->exists());
        self::assertTrue(DB::connection(self::LANDLORD_REPLICA_CONNECTION)->table(self::GRANTS)->where('id', $id)->exists());
    }

    /**
     * An access that lets a principal use the application only with a grant,
     * read through the query builder on the landlord connection, which is the
     * principal's.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationAccess
     */
    private function access(): ApplicationAccess
    {
        $access = self::createStub(ApplicationAccess::class);

        $access->method('mayUse')->willReturnCallback(
            static fn (string $guard, Principal $principal): bool => DB::connection(self::LANDLORD_CONNECTION)
                ->table(self::GRANTS)
                ->where('principal_id', $principal->getPrincipalIdentifier())
                ->exists(),
        );

        return $access;
    }
}
