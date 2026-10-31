<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoices;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Proves the principals an identity may choose or switch to are read from the
 * write connection: a membership the primary has just added is offered while
 * the replica still lacks it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalChoices::class)]
#[CoversClass(SessionService::class)]
final class ReplicaChoosesPrincipalsTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessions;

    /** @var string Guard over the choosing members. */
    private const string GUARD = 'choosers';

    /**
     * Create the member, membership and tenant tables on the primary and the
     * replica.
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
     * A membership only the primary holds is listed, and a password sign-in
     * offers it as a choice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMembershipOnlyThePrimaryHoldsIsOffered(): void
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $tenant = ActivatableTenant::query()->create(['name' => 'New', 'is_active' => true]);

        $this->copyRowToReplica('activatable_tenant_members', $member->id);
        $this->copyRowToReplica('activatable_tenants', $tenant->getKey());

        $membership = ChoosingMembership::query()->create(['identity_id' => $member->id, 'tenant_id' => $tenant->getKey()]);

        self::assertSame(0, ChoosingMembership::query()->count());

        $keys = static fn (array $principals): array => array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $principals);

        self::assertSame([$membership->id], $keys($this->sessions(self::GUARD)->principals($member)));

        $choice = $this->sessions(self::GUARD)->signIn('password', self::credentials('chooser@example.test'))->choice;

        self::assertNotNull($choice);
        self::assertSame([$membership->id], $keys($choice->principals));
    }

    /**
     * Configure the guards over a lagging read/write split, and a guard over
     * the choosing members.
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

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);

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
