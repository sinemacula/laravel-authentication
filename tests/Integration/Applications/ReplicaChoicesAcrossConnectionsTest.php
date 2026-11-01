<?php

declare(strict_types = 1);

namespace Tests\Integration\Applications;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\ApplicationAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoices;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\LandlordPrincipal;
use Tests\Integration\Fixtures\LandlordPrincipalMember;
use Tests\TestCase;

/**
 * Proves the principals offered to an identity are admitted with the
 * application policy's reads on the identity's write connection, also when the
 * principals live on another connection: the identity is on the lagging default
 * split, its principals on the lagging `landlord` split, and the policy reads
 * its grants on the identity's connection, so pinning the principal's
 * connection alone would answer from a replica that still holds a withdrawn
 * grant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalChoices::class)]
#[CoversClass(ApplicationAdmission::class)]
final class ReplicaChoicesAcrossConnectionsTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessions;

    /** @var string Guard over the members whose principals live on the landlord connection. */
    private const string GUARD = 'landlord_members';

    /** @var string Table of the principals the policy admits, each for no identifier type or for one. */
    private const string GRANTS = 'principal_grants';

    /**
     * Create the member and grant tables on the default primary and replica,
     * the principal table on the landlord primary and replica, and bind the
     * policy that reads the grants.
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
            $blueprint->string('identifier_type');
        });

        $this->createOnPrimaryAndReplica('landlord_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->timestamps();
        }, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);

        app()->instance(ApplicationPolicy::class, $this->policy());
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
     * A principal whose grant for no identifier type the primary has withdrawn
     * is offered neither with nor without an identifier type, and one whose
     * grant for the type the primary has withdrawn is no longer offered with
     * that type, though the replica still holds both grants.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsAreAdmittedOnTheIdentitysPrimary(): void
    {
        $member = LandlordPrincipalMember::query()->create(['email' => 'member@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $first  = LandlordPrincipal::query()->create(['identity_id' => $member->id]);
        $second = LandlordPrincipal::query()->create(['identity_id' => $member->id]);

        $untyped = $this->grant($first, '');

        $this->grant($first, 'email');
        $this->grant($second, '');

        $email = $this->grant($second, 'email');

        self::assertSame([$first->id, $second->id], $this->offered($member, null));
        self::assertSame([$first->id, $second->id], $this->offered($member, 'email'));

        $this->withdrawOnThePrimary($untyped);

        self::assertSame([$second->id], $this->offered($member, null));
        self::assertSame([$second->id], $this->offered($member, 'email'));

        $this->withdrawOnThePrimary($email);

        self::assertSame([$second->id], $this->offered($member, null));
        self::assertSame([], $this->offered($member, 'email'));
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
     * Grant the principal the application for the identifier type (`''` for
     * none), on the default primary only.
     *
     * @param  \Tests\Integration\Fixtures\LandlordPrincipal  $principal
     * @param  string  $identifierType
     * @return int
     */
    private function grant(LandlordPrincipal $principal, string $identifierType): int
    {
        return DB::table(self::GRANTS)->insertGetId(['principal_id' => $principal->id, 'identifier_type' => $identifierType]);
    }

    /**
     * Copy the grant to the default replica, then delete it on the primary, as
     * a replica that lags behind the withdrawal would still hold it.
     *
     * @param  int  $id
     * @return void
     */
    private function withdrawOnThePrimary(int $id): void
    {
        $this->copyRowToReplica(self::GRANTS, $id);

        DB::table(self::GRANTS)->where('id', $id)->delete();

        self::assertFalse(DB::connection(self::PRIMARY_CONNECTION)->table(self::GRANTS)->where('id', $id)->exists());
        self::assertTrue(DB::connection(self::REPLICA_CONNECTION)->table(self::GRANTS)->where('id', $id)->exists());
    }

    /**
     * A policy that admits a principal only with a grant for the identifier
     * type the sign-in used (`''` for none), read through the query builder on
     * the default connection, which is the identity's, and admits every
     * identity.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy
     */
    private function policy(): ApplicationPolicy
    {
        $policy = self::createStub(ApplicationPolicy::class);

        $policy->method('admit')->willReturnCallback(
            static fn (string $guard, Identity $identity, Principal $principal, ?string $identifierType): ?FailureReason => DB::table(self::GRANTS)
                ->where('principal_id', $principal->getPrincipalIdentifier())
                ->where('identifier_type', $identifierType ?? '')
                ->exists() ? null : FailureReason::PRINCIPAL_INELIGIBLE,
        );

        return $policy;
    }
}
