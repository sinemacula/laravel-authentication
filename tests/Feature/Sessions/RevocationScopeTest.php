<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasswordChange;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Integration\Fixtures\AccessOnlyMember;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\Integration\Fixtures\SavingCutoffIdentity;
use Tests\TestCase;

/**
 * Feature tests of a principal's revocation scope: whether it has sessions is
 * decided by its owner as stored, read afresh, never by an identity relation
 * whoever loaded the principal set on it; an owner that cannot be read does not
 * stop its sessions being ended, and neither does Eloquent strict mode.
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

        Schema::create('saving_cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
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

        Schema::dropIfExists('saving_cutoff_identities');
        Schema::dropIfExists('cutoff_identities');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A membership whose identity relation was set to an identity that holds no
     * sessions still has its sessions revoked: its stored owner holds them, and
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

        self::assertSame(1, $this->sessions('members')->revokePrincipalSessions($membership, RevocationReason::REVOKED));
        self::assertSame('revoked', DB::table('authentication_sessions')->value('revoked_reason'));

        $context = $this->recorded[0]->context ?? null;

        self::assertNotNull($context);
        EventContextAssertions::assertIdentity($member, $context);
    }

    /**
     * A membership whose owner can no longer be read (its row deleted) still
     * has its sessions revoked: an unreadable owner might hold sessions, so
     * they are looked for, and the scope carries no identity.
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

        self::assertSame(1, $this->sessions('members')->revokePrincipalSessions($stored, RevocationReason::REVOKED));
        self::assertSame(0, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        EventContextAssertions::assertIdentity(null, $this->recordedEvent(SignedOutEverywhere::class)->context);
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

        self::assertSame(1, $this->sessions('members')->revokePrincipalSessions($memberships->firstOrFail(), RevocationReason::REVOKED));
        self::assertTrue($membership->is($memberships->first()));

        EventContextAssertions::assertIdentity($member, $this->recordedEvent(SignedOutEverywhere::class)->context);
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

        $this->sessions()->revokePrincipalSessions($identity, RevocationReason::REVOKED);

        EventContextAssertions::assertIdentity($identity, $this->recordedEvent(SignedOutEverywhere::class)->context);
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
     * Keeping the cutoff leaves the scope's sessions and parts as they were and
     * drops only the cutoff to move.
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
        self::assertSame($scope->sessions, $kept->sessions);
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
     * Only a stored model's cutoff is moved: once a hard delete removes the
     * row, an identity's scope and a principal's still hold its sessions but no
     * cutoff, as does an identity never saved, so a `HasTokensValidAfter` that
     * persists through `save()` never inserts the row again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAModelThatIsNotStoredHasNoCutoffToMove(): void
    {
        $identity = SavingCutoffIdentity::query()->create(['email' => 'saving@example.test', 'password' => 'unused']);

        self::assertSame($identity, RevocationScope::identity($identity)->cutoff);
        self::assertSame($identity, RevocationScope::principal($identity)->cutoff);

        $identity->delete();

        $identityScope  = RevocationScope::identity($identity);
        $principalScope = RevocationScope::principal($identity);

        self::assertNull($identityScope->cutoff);
        self::assertNotNull($identityScope->sessions);
        self::assertNull($principalScope->cutoff);
        self::assertNotNull($principalScope->sessions);
        self::assertNull(RevocationScope::identity(new CutoffIdentity)->cutoff);

        self::assertSame(0, $this->sessions()->identityDeleted($identity));
        self::assertSame(0, $this->sessions()->principalDeleted($identity));
        self::assertSame(0, DB::table('saving_cutoff_identities')->count());
    }

    /**
     * A reference to a stored identity by its key alone is not loaded from its
     * row (`exists` is `false`): its sessions end, but its cutoff stays where
     * it is, while the model loaded from the row has its cutoff moved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReferenceByKeyEndsItsSessionsButMovesNoCutoff(): void
    {
        $stored    = $this->cutoffIdentity();
        $reference = new CutoffIdentity;

        $reference->setAttribute('id', $stored->getKey());

        $this->insertSession(CutoffIdentity::class, $stored->id);

        self::assertNull(RevocationScope::identity($reference)->cutoff);
        self::assertSame(1, $this->sessions()->passwordReset($reference));
        self::assertSame(RevocationReason::PASSWORD_RESET->value, DB::table('authentication_sessions')->value('revoked_reason'));
        self::assertNull(DB::table('cutoff_identities')->value('tokens_valid_after'));

        $this->sessions()->passwordReset($stored);

        self::assertNotNull(DB::table('cutoff_identities')->value('tokens_valid_after'));
    }

    /**
     * An observer revokes once the transaction commits, on the model as it is
     * then: a password change and a hard delete committed together end the
     * sessions with no cutoff moved, so a `HasTokensValidAfter` that persists
     * through `save()` never inserts the deleted row again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAModelDeletedBeforeTheCommitHasNoCutoffToMove(): void
    {
        $identity = SavingCutoffIdentity::query()->create(['email' => 'saving@example.test', 'password' => 'unused']);

        $this->insertSession(SavingCutoffIdentity::class, $identity->id);

        SavingCutoffIdentity::observe(RevokeSessionsOnPasswordChange::class);

        $this->recordEvents([SignedOutEverywhere::class]);

        DB::transaction(static function () use ($identity): void {
            $identity->update(['password' => 'changed']);
            $identity->delete();
        });

        self::assertSame(0, DB::table('saving_cutoff_identities')->count());
        self::assertSame(RevocationReason::PASSWORD_CHANGED->value, DB::table('authentication_sessions')->value('revoked_reason'));
        self::assertSame(1, $this->recordedEvent(SignedOutEverywhere::class)->revoked);
        self::assertNull($this->recordedEvent(SignedOutEverywhere::class)->tokensValidAfter);
    }

    /**
     * An identity or principal that is not an Eloquent model has no stored
     * state to ask about, so its cutoff is the scope's to move.
     *
     * @return void
     */
    public function testAHolderThatIsNotAModelKeepsItsCutoff(): void
    {
        $identity = \Mockery::mock(Identity::class, HasTokensValidAfter::class);

        self::assertSame($identity, RevocationScope::identity($identity)->cutoff);

        $owner     = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class, HasTokensValidAfter::class);

        $principal->shouldReceive('getIdentity')->andReturn($owner);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn(7);

        $scope = RevocationScope::principal($principal);

        self::assertSame($principal, $scope->cutoff);
        self::assertSame($owner, $scope->identity);
        self::assertNull($scope->sessions);
    }

    /**
     * A tenant's scope holds every session acting in it, of every guard and
     * whatever principal it acts as, and no session acting elsewhere; it has no
     * cutoff and no identity or principal of its own. A tenant without an
     * identifier holds no session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsScopeHoldsTheSessionsActingInIt(): void
    {
        $tenant = ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);
        $key    = IdentifierCoercion::stringify($tenant->getKey());

        foreach ([['api', $key], ['members', $key], ['api', 'another'], ['api', null]] as [$guard, $tenantId]) {
            DB::table('authentication_sessions')->insert([
                'id'                   => (string) Str::uuid7(),
                'generation'           => (string) Str::uuid7(),
                'authenticatable_type' => 'user',
                'authenticatable_id'   => '1',
                'guard'                => $guard,
                'tenant_id'            => $tenantId,
                'signed_in_at'         => Carbon::now(),
                'idle_expires_at'      => Carbon::now()->addDay(),
            ]);
        }

        $scope = RevocationScope::activeTenant($tenant);

        self::assertNotNull($scope->sessions);
        self::assertSame([$key, $key], $scope->sessions[0]->pluck('tenant_id')->all());
        self::assertNull($scope->cutoff);
        self::assertNull($scope->identity);
        self::assertNull($scope->principal);
        self::assertSame($tenant, $scope->tenant);
        self::assertSame([], $scope->changes);

        $unsaved = RevocationScope::activeTenant(new ActivatableTenant);

        self::assertNull($unsaved->sessions);
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
     * Persist an identity that records a cutoff and holds sessions.
     *
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function cutoffIdentity(): CutoffIdentity
    {
        return CutoffIdentity::query()->create(['email' => 'cutoff@example.test', 'password' => 'unused']);
    }

    /**
     * Insert a live session of the "api" guard held by the identity of the type
     * and key given.
     *
     * @param  class-string  $type
     * @param  int  $id
     * @return void
     */
    private function insertSession(string $type, int $id): void
    {
        DB::table('authentication_sessions')->insert([
            'id'                   => (string) Str::uuid7(),
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $type,
            'authenticatable_id'   => (string) $id,
            'guard'                => 'api',
            'signed_in_at'         => Carbon::now(),
            'idle_expires_at'      => Carbon::now()->addDay(),
        ]);
    }
}
