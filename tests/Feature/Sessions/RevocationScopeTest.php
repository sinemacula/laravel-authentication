<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\AccessOnlyMember;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\TestCase;

/**
 * Feature tests of a principal's revocation scope: whether its sessions can
 * hold devices is decided by its owner as stored, read afresh, never by an
 * identity relation whoever loaded the principal set on it; an owner that
 * cannot be read does not stop its sessions being ended, and neither does
 * Eloquent strict mode.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevocationScope::class)]
final class RevocationScopeTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Model::preventLazyLoading(false);

        Schema::dropIfExists('cutoff_identities');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A membership whose identity relation was set to an identity that holds no
     * devices still has its sessions revoked: its stored owner holds them, and
     * the scope carries that owner.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityRelationSetOnThePrincipalDoesNotStandInForItsOwner(): void
    {
        [$member, $membership] = $this->seedMember();

        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member@example.test'))->isSignedIn());

        $membership->setRelation('identity', new AccessOnlyMember);

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(1, $this->sessions('members')->revokePrincipalDevices($membership, RevocationReason::REVOKED));
        self::assertSame('revoked', DB::table('devices')->value('revoked_reason'));

        $identity = $this->recorded[0]->context->identity ?? null;

        self::assertInstanceOf(ActivatableTenantMember::class, $identity);
        self::assertSame($member->getKey(), $identity->getKey());
    }

    /**
     * A membership whose owner can no longer be read (its row deleted) still
     * has its sessions revoked: an unreadable owner might hold devices, so they
     * are looked for, and the scope carries no identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalWhoseOwnerCannotBeReadStillHasItsSessionsEnded(): void
    {
        [$member, $membership] = $this->seedMember();

        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member@example.test'))->isSignedIn());

        DB::table('activatable_tenant_members')->where('id', $member->getKey())->delete();

        $this->recordEvents([SignedOutEverywhere::class]);

        $stored = ActivatableTenantMembership::query()->findOrFail($membership->getKey());

        self::assertSame(1, $this->sessions('members')->revokePrincipalDevices($stored, RevocationReason::REVOKED));
        self::assertSame(0, DB::table('devices')->whereNull('revoked_at')->count());
        self::assertNull($this->recordedEvent(SignedOutEverywhere::class)->context->identity);
        self::assertSame(1, $this->recordedEvent(SignedOutEverywhere::class)->revoked);
    }

    /**
     * A membership hydrated with others in one collection while Eloquent
     * prevents lazy loading (strict mode) has its owner read all the same, and
     * its sessions are ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalHydratedUnderStrictModeHasItsOwnerReadAllTheSame(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $this->seedMember('second@example.test', $tenant);

        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member@example.test'))->isSignedIn());

        Model::preventLazyLoading();

        $memberships = ActivatableTenantMembership::query()->orderBy('id')->get();

        self::assertTrue($memberships->first()?->preventsLazyLoading);

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(1, $this->sessions('members')->revokePrincipalDevices($memberships->firstOrFail(), RevocationReason::REVOKED));
        self::assertTrue($membership->is($memberships->first()));

        $identity = $this->recordedEvent(SignedOutEverywhere::class)->context->identity;

        self::assertInstanceOf(ActivatableTenantMember::class, $identity);
        self::assertSame($member->getKey(), $identity->getKey());
        self::assertFalse($memberships->firstOrFail()->relationLoaded('identity'));
    }

    /**
     * A principal that is its own identity (2D) is carried as that very
     * identity, with no owner read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalThatIsItsOwnIdentityIsCarriedAsIt(): void
    {
        $identity = $this->seedIdentity();

        $this->recordEvents([SignedOutEverywhere::class]);

        $this->sessions()->revokePrincipalDevices($identity, RevocationReason::REVOKED);

        self::assertSame($identity, $this->recordedEvent(SignedOutEverywhere::class)->context->identity);
    }

    /**
     * An identity's scope carries the keys of its pending identifier changes of
     * the types given, none when none are given; a principal's carries none,
     * and keeping the cutoff keeps them.
     *
     * @return void
     */
    public function testAnIdentityScopeCarriesTheKeysOfItsPendingChanges(): void
    {
        $identity = $this->cutoffIdentity();
        $scope    = RevocationScope::identity($identity, ['email', 'phone']);

        self::assertSame([PendingChanges::key($identity, 'email'), PendingChanges::key($identity, 'phone')], $scope->changes);
        self::assertSame($scope->changes, $scope->keepingCutoff()->changes);
        self::assertSame([], RevocationScope::identity($identity)->changes);
        self::assertSame([], RevocationScope::principal($identity)->changes);
    }

    /**
     * Keeping the cutoff leaves the scope's devices, pending sign-ins and parts
     * as they were and drops only the cutoff to move.
     *
     * @return void
     */
    public function testKeepingTheCutoffDropsOnlyTheCutoff(): void
    {
        $identity = $this->cutoffIdentity();
        $scope    = RevocationScope::identity($identity);
        $kept     = $scope->keepingCutoff();

        self::assertSame($identity, $scope->cutoff);
        self::assertNull($kept->cutoff);
        self::assertSame($scope->devices, $kept->devices);
        self::assertSame($scope->pendings, $kept->pendings);
        self::assertSame($scope->changes, $kept->changes);
        self::assertSame($identity, $kept->identity);
        self::assertNull($kept->principal);
        self::assertNull($kept->tenant);

        $tenant    = ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);
        $principal = RevocationScope::principal($identity, $tenant)->keepingCutoff();

        self::assertSame($identity, $principal->principal);
        self::assertSame($tenant, $principal->tenant);
    }

    /**
     * Register the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Persist an identity that records a cutoff and holds devices.
     *
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function cutoffIdentity(): CutoffIdentity
    {
        return CutoffIdentity::query()->create(['email' => 'cutoff@example.test', 'password' => 'unused']);
    }
}
