<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnDeletion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\SavingCutoffIdentity;
use Tests\Integration\Fixtures\SoftDeletingMember;
use Tests\Integration\Fixtures\SoftDeletingMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\StubModel;

/**
 * Feature tests of the optional `RevokeSessionsOnDeletion` observer, registered
 * by the test as an application registers it: deleting an identity ends every
 * session it holds, and deleting a principal every session acting as it, once
 * the delete commits; a soft delete counts, a restore brings nothing back, and
 * a later force delete revokes only a session written since.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnDeletion::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class RevokeSessionsOnDeletionTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClocksTo(CarbonImmutable::parse(self::NOW));

        $this->createSessionTables();

        Schema::create('soft_deleting_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        Schema::create('soft_deleting_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
            $blueprint->softDeletes();
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
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('saving_cutoff_identities');
        Schema::dropIfExists('soft_deleting_memberships');
        Schema::dropIfExists('soft_deleting_members');

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Deleting an identity revokes every session it holds, pending ones and
     * those acting as each of its principals included, with `identity_deleted`,
     * reporting each and then the identity signed out everywhere; another
     * identity's session is left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAnIdentityRevokesEverySessionItHolds(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();
        [$other, $theirs]               = $this->seedMember('other@example.test', $tenant);

        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $ended  = [self::insertSession($member, $membership), self::insertSession($member, $second), self::insertSession($member, $membership, 'pending')];
        $kept   = self::insertSession($other, $theirs);

        ActivatableTenantMember::observe(RevokeSessionsOnDeletion::class);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        $member->delete();

        self::assertSame(array_fill(0, 3, 'identity_deleted'), DB::table('authentication_sessions')->whereIn('id', $ended)->pluck('revoked_reason')->all());
        self::assertNull(DB::table('authentication_sessions')->where('id', $kept)->value('revoked_at'));
        self::assertSame([SessionRevoked::class, SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());

        $revoked = array_values(array_filter($this->recorded, static fn (object $event): bool => $event instanceof SessionRevoked));

        self::assertSame(array_fill(0, 3, RevocationReason::IDENTITY_DELETED), array_map(static fn (SessionRevoked $event): RevocationReason => $event->reason, $revoked));
        self::assertEqualsCanonicalizing($ended, array_map(static fn (SessionRevoked $event): ?string => $event->context->sessionId, $revoked));

        $scope = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame(RevocationReason::IDENTITY_DELETED, $scope->reason);
        self::assertSame(3, $scope->revoked);
        self::assertSame((string) $member->id, $scope->context->identityId);
        self::assertNull($scope->context->principalId);
    }

    /**
     * Deleting a principal revokes only the sessions acting as it, pending ones
     * included, with `principal_deleted`; its owner's session acting as another
     * principal stays live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAPrincipalRevokesOnlyTheSessionsActingAsIt(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $other = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $ended = [self::insertSession($member, $membership), self::insertSession($member, $membership, 'pending')];
        $kept  = self::insertSession($member, $other);

        ActivatableTenantMembership::observe(RevokeSessionsOnDeletion::class);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        $membership->delete();

        self::assertSame(['principal_deleted', 'principal_deleted'], DB::table('authentication_sessions')->whereIn('id', $ended)->pluck('revoked_reason')->all());
        self::assertNull(DB::table('authentication_sessions')->where('id', $kept)->value('revoked_at'));
        self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());

        foreach (array_slice($this->recorded, 0, 2) as $event) {
            self::assertInstanceOf(SessionRevoked::class, $event);
            self::assertSame(RevocationReason::PRINCIPAL_DELETED, $event->reason);
            self::assertSame((string) $membership->id, $event->context->principalId);
        }

        $scope = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame(RevocationReason::PRINCIPAL_DELETED, $scope->reason);
        self::assertSame(2, $scope->revoked);
        self::assertSame((string) $membership->id, $scope->context->principalId);
        self::assertSame((string) $member->id, $scope->context->identityId);
    }

    /**
     * A model that is both identity and principal (2D) is treated as the
     * identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATwoDimensionalModelIsTreatedAsTheIdentity(): void
    {
        $identity = $this->seedIdentity();
        $session  = self::insertSession($identity, $identity);

        IntegrationIdentity::observe(RevokeSessionsOnDeletion::class);

        $this->recordEvents([SignedOutEverywhere::class]);

        $identity->delete();

        self::assertSame('identity_deleted', DB::table('authentication_sessions')->where('id', $session)->value('revoked_reason'));
        self::assertNull($this->recordedEvent(SignedOutEverywhere::class)->context->principalId);
    }

    /**
     * Deleting a model that is neither an identity nor a principal, such as a
     * tenant, cannot end its sessions here: the observer was registered where
     * it cannot act, which is reported, and nothing is revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAModelThatIsNeitherIsReported(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        self::insertSession($member, $membership);

        ActivatableTenant::observe(RevokeSessionsOnDeletion::class);

        foreach ([$tenant, new StubModel] as $model) {

            try {
                $model instanceof StubModel ? app(RevokeSessionsOnDeletion::class)->deleted($model) : $model->delete();

                self::fail('Deleting ' . $model::class . ' was not reported.');
            } catch (\LogicException $exception) {
                self::assertSame(
                    'Model ' . $model::class . ' is neither an identity nor a principal, so deleting it ends no sessions here.'
                    . ' A tenant\'s sessions end through tenantDeactivated() with its principals.',
                    $exception->getMessage(),
                );
            }
        }

        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * A soft delete counts as deletion: an identity's sessions end with
     * `identity_deleted` and its cutoff moves to now, and a principal's with
     * `principal_deleted` and its own cutoff moves.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASoftDeleteCountsAsDeletion(): void
    {
        [$member, $membership] = $this->seedSoftDeletingMember();
        [$other, $theirs]      = $this->seedSoftDeletingMember('other@example.test');

        $identitySession  = self::insertSession($member, $membership);
        $principalSession = self::insertSession($other, $theirs);

        SoftDeletingMember::observe(RevokeSessionsOnDeletion::class);
        SoftDeletingMembership::observe(RevokeSessionsOnDeletion::class);

        $member->delete();
        $theirs->delete();

        self::assertTrue($member->trashed());
        self::assertTrue($theirs->trashed());
        self::assertSame('identity_deleted', DB::table('authentication_sessions')->where('id', $identitySession)->value('revoked_reason'));
        self::assertSame('principal_deleted', DB::table('authentication_sessions')->where('id', $principalSession)->value('revoked_reason'));
        self::assertSame(self::NOW, DB::table('soft_deleting_members')->where('id', $member->id)->value('tokens_valid_after'));
        self::assertNull(DB::table('soft_deleting_members')->where('id', $other->id)->value('tokens_valid_after'));
        self::assertSame(self::NOW, DB::table('soft_deleting_memberships')->where('id', $theirs->id)->value('tokens_valid_after'));
        self::assertNull(DB::table('soft_deleting_memberships')->where('id', $membership->id)->value('tokens_valid_after'));
    }

    /**
     * Restoring a soft-deleted identity or principal brings no session back:
     * each keeps its revocation, and nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARestoreBringsNoSessionBack(): void
    {
        [$member, $membership] = $this->seedSoftDeletingMember();

        $session = self::insertSession($member, $membership);

        SoftDeletingMember::observe(RevokeSessionsOnDeletion::class);
        SoftDeletingMembership::observe(RevokeSessionsOnDeletion::class);

        $member->delete();
        $membership->delete();

        $this->moveClocksTo(CarbonImmutable::parse(self::NOW)->addMinute());
        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertTrue($member->restore()); // @phpstan-ignore staticMethod.dynamicCall
        self::assertTrue($membership->restore()); // @phpstan-ignore staticMethod.dynamicCall

        $row = DB::table('authentication_sessions')->where('id', $session)->first(['revoked_at', 'revoked_reason']);

        self::assertNotNull($row);
        self::assertSame('identity_deleted', $row->revoked_reason);
        self::assertSame(self::NOW, CarbonImmutable::parse($row->revoked_at)->format('Y-m-d H:i:s'));
        self::assertSame([], $this->recorded);
    }

    /**
     * A force delete after a soft delete runs the revocation again and revokes
     * nothing more: no session changes or is reported, and the identity is
     * reported signed out everywhere of none, its cutoff gone with its row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAForceDeleteAfterASoftDeleteRevokesNothingMore(): void
    {
        [$member, $membership] = $this->seedSoftDeletingMember();

        $session = self::insertSession($member, $membership);

        SoftDeletingMember::observe(RevokeSessionsOnDeletion::class);

        $member->delete();

        $this->moveClocksTo(CarbonImmutable::parse(self::NOW)->addMinute());
        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertTrue($member->forceDelete());

        $scope = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame([SignedOutEverywhere::class], $this->recordedClasses());
        self::assertSame(RevocationReason::IDENTITY_DELETED, $scope->reason);
        self::assertSame(0, $scope->revoked);
        self::assertNull($scope->tokensValidAfter);
        self::assertSame(self::NOW, self::storedInstant(DB::table('authentication_sessions')->where('id', $session)->value('revoked_at'))->format('Y-m-d H:i:s'));
        self::assertSame(0, DB::table('soft_deleting_members')->count());
    }

    /**
     * A session written after a restore, while the identity is live again, is
     * ended by a later force delete; the session the soft delete ended keeps
     * its first revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAForceDeleteEndsASessionWrittenSinceTheRestore(): void
    {
        [$member, $membership] = $this->seedSoftDeletingMember();

        $earlier = self::insertSession($member, $membership);

        SoftDeletingMember::observe(RevokeSessionsOnDeletion::class);

        $member->delete();
        $member->restore(); // @phpstan-ignore staticMethod.dynamicCall

        $this->moveClocksTo(CarbonImmutable::parse(self::NOW)->addMinute());

        $later = self::insertSession($member, $membership);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        $member->forceDelete();

        self::assertSame($later, $this->recordedEvent(SessionRevoked::class)->context->sessionId);
        self::assertSame(1, $this->recordedEvent(SignedOutEverywhere::class)->revoked);
        self::assertSame(self::NOW, self::storedInstant(DB::table('authentication_sessions')->where('id', $earlier)->value('revoked_at'))->format('Y-m-d H:i:s'));
        self::assertSame('identity_deleted', DB::table('authentication_sessions')->where('id', $later)->value('revoked_reason'));
    }

    /**
     * A force delete of a live model revokes its sessions once, and its row
     * stays gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAForceDeleteOfALiveModelRevokesOnceWithoutRestoringItsRow(): void
    {
        [$member, $membership] = $this->seedSoftDeletingMember();

        $sessions = [self::insertSession($member, $membership), self::insertSession($member, $membership)];

        SoftDeletingMember::observe(RevokeSessionsOnDeletion::class);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        $member->forceDelete();

        self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());
        self::assertSame(['identity_deleted', 'identity_deleted'], DB::table('authentication_sessions')->whereIn('id', $sessions)->pluck('revoked_reason')->all());
        self::assertNull($this->recordedEvent(SignedOutEverywhere::class)->tokensValidAfter);
        self::assertSame(0, DB::table('soft_deleting_members')->count());
    }

    /**
     * A hard delete moves no cutoff, so an identity whose own
     * `HasTokensValidAfter` persists it through `save()` is not inserted again:
     * its sessions end and its row stays gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHardDeleteNeverSavesTheCutoffOfTheRowItRemoved(): void
    {
        $identity = SavingCutoffIdentity::query()->create(['email' => 'saving@example.test', 'password' => 'unused']);
        $session  = self::insertSession($identity, $identity);

        SavingCutoffIdentity::observe(RevokeSessionsOnDeletion::class);

        $this->recordEvents([SignedOutEverywhere::class]);

        $identity->delete();

        self::assertSame(0, DB::table('saving_cutoff_identities')->count());
        self::assertSame('identity_deleted', DB::table('authentication_sessions')->where('id', $session)->value('revoked_reason'));
        self::assertSame(1, $this->recordedEvent(SignedOutEverywhere::class)->revoked);
        self::assertNull($this->recordedEvent(SignedOutEverywhere::class)->tokensValidAfter);
    }

    /**
     * A delete that is rolled back revokes nothing, and the row is back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeleteRolledBackRevokesNothing(): void
    {
        [$member, $membership] = $this->seedMember();

        self::insertSession($member, $membership);

        ActivatableTenantMember::observe(RevokeSessionsOnDeletion::class);
        ActivatableTenantMembership::observe(RevokeSessionsOnDeletion::class);

        try {
            DB::transaction(static function () use ($member, $membership): never {
                $membership->delete();
                $member->delete();

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('roll back', $exception->getMessage());
        }

        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertSame(1, ActivatableTenantMember::query()->whereKey($member->getKey())->count());
        self::assertSame(1, ActivatableTenantMembership::query()->whereKey($membership->getKey())->count());
    }

    /**
     * A delete inside a caller's transaction revokes nothing until it commits,
     * then the sessions.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeleteInATransactionRevokesOnlyOnceItCommits(): void
    {
        [$member, $membership] = $this->seedMember();

        $session = self::insertSession($member, $membership);

        ActivatableTenantMember::observe(RevokeSessionsOnDeletion::class);

        DB::transaction(static function () use ($member): void {

            $member->delete();

            self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        });

        self::assertSame('identity_deleted', DB::table('authentication_sessions')->where('id', $session)->value('revoked_reason'));
    }

    /**
     * Register the session guards, the `api` guard as the default.
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

        $app->make(ConfigRepository::class)->set('auth.defaults.guard', 'api');
    }

    /**
     * Persist a soft-deleting member with one membership.
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\SoftDeletingMember, 1: \Tests\Integration\Fixtures\SoftDeletingMembership}
     */
    private function seedSoftDeletingMember(string $email = 'member@example.test'): array
    {
        $member = SoftDeletingMember::query()->create(['email' => $email, 'password' => 'unused']);

        $membership = SoftDeletingMembership::query()->create(['identity_id' => $member->id]);

        return [$member, $membership];
    }

    /**
     * Insert a session of the identity acting as the principal, live, and
     * return its id.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  \Illuminate\Database\Eloquent\Model  $principal
     * @param  string  $status
     * @return string
     */
    private static function insertSession(Model $identity, Model $principal, string $status = 'active'): string
    {
        $id = (string) Str::uuid7();

        DB::table('authentication_sessions')->insert([
            'id'                   => $id,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $principal->getMorphClass(),
            'principal_id'         => (string) $principal->getKey(), // @phpstan-ignore cast.string
            'status'               => $status,
            'guard'                => 'members',
            'signed_in_at'         => now(),
            'idle_expires_at'      => now()->addDay(),
            'absolute_expires_at'  => now()->addWeek(),
        ]);

        return $id;
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function moveClocksTo(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);
    }
}
