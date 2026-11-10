<?php

declare(strict_types = 1);

namespace Tests\Feature\Admission;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Eloquent\SoftDeletingScope;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\PrincipalListing;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\CustomTenantMembership;
use Tests\Integration\Fixtures\DefaultTenantMembership;
use Tests\Integration\Fixtures\MorphTenantMembership;
use Tests\Integration\Fixtures\ParentedTenant;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\Integration\Fixtures\WorkspaceMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * Feature tests of listing an identity's principals for admission against a
 * real database: the active principals judged have their tenants read together
 * in one query per principal class, after the principals' own query and as a
 * lazy load would read them, with a tenant that read misses read alone, and are
 * judged as stored with only that tenant carried; an inactive principal is
 * refused without its tenant being read, and a principal the resolver supplied
 * carries nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalListing::class)]
final class PrincipalListingTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The guard the principals are judged for. */
    private const string GUARD = 'api';

    /** @var string A second connection holding principals and tenants of its own. */
    private const string ELSEWHERE = 'elsewhere';

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

        Schema::create('parented_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('parent_id')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('morph_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('tenant_type')->nullable();
            $blueprint->unsignedInteger('tenant_id')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('typed_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->timestamps();
        });

        Schema::create('keyed_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('tenant_type')->nullable();
            $blueprint->string('tenant_id')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the tables and allow lazy loading again.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Model::preventLazyLoading(false);

        Schema::dropIfExists('keyed_memberships');
        Schema::dropIfExists('typed_tenants');
        Schema::dropIfExists('morph_tenant_memberships');
        Schema::dropIfExists('parented_tenants');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * The identity's principals are listed in one query, and judging them reads
     * every one's tenant in one more, whatever each tenant's state; each
     * principal listed then holds the tenant judged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsJudgedHaveTheirTenantsReadInOneQuery(): void
    {
        [$member, $memberships] = $this->seedChooser(3);

        ActivatableTenant::query()->whereKey($memberships[1]->tenant_id)->update(['is_active' => false]);

        $listing = null;

        self::assertCount(1, $this->queries(static function () use ($member, &$listing): void {
            $listing = PrincipalListing::of($member);
        }));

        self::assertInstanceOf(PrincipalListing::class, $listing);

        $candidates = self::principalsOf($listing);
        $refusals   = null;
        $queries    = $this->queries(static function () use ($listing, $candidates, &$refusals): void {
            $refusals = $listing->refusals(self::GUARD, $candidates);
        });

        self::assertSame([null, FailureReason::TENANT_INACTIVE, null], $refusals);
        self::assertCount(1, $queries);
        self::assertStringContainsString(self::wrapped('activatable_tenants'), $queries[0]);
        self::assertSame(array_map(static fn (ChoosingMembership $membership): int => $membership->tenant_id, $memberships), array_map(self::tenantKeyOf(...), $candidates));
    }

    /**
     * Only the principals judged have their tenants loaded: judging one of
     * three reads its tenant alone and leaves the others as they were listed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyThePrincipalsJudgedHaveTheirTenantsLoaded(): void
    {
        [$member] = $this->seedChooser(3);

        $listing    = PrincipalListing::of($member);
        $candidates = self::principalsOf($listing);

        self::assertSame([null], $listing->refusals(self::GUARD, [$candidates[1]]));
        self::assertSame([false, true, false], array_map(self::tenantLoadedOn(...), $candidates));
        self::assertSame([], $listing->refusals(self::GUARD, []));
    }

    /**
     * Under Eloquent strict mode the principals, read together, stay strict,
     * while the tenants judged allow lazy loading as a tenant read on its own
     * does: a tenant whose activity reads its parent is judged by it, and each
     * listed principal answers `getTenant()` without a lazy load of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantsAllowLazyLoadingWhileThePrincipalsStayStrict(): void
    {
        $parent   = ParentedTenant::query()->create(['is_active' => false]);
        $orphan   = ParentedTenant::query()->create(['is_active' => true]);
        $child    = ParentedTenant::query()->create(['is_active' => true, 'parent_id' => $parent->getKey()]);
        $identity = $this->identityListing(WorkspaceMembership::query()->orderBy('id'));

        $first  = WorkspaceMembership::query()->create(['identity_id' => 1, 'tenant_id' => $orphan->getKey()]);
        $second = WorkspaceMembership::query()->create(['identity_id' => 1, 'tenant_id' => $child->getKey()]);

        Model::preventLazyLoading();

        $listing    = PrincipalListing::of($identity);
        $candidates = self::principalsOf($listing);

        self::assertSame([null, FailureReason::TENANT_INACTIVE], $listing->refusals(self::GUARD, $candidates));

        foreach ($candidates as $candidate) {

            self::assertInstanceOf(WorkspaceMembership::class, $candidate);
            self::assertTrue($candidate->preventsLazyLoading);

            $workspace = $candidate->getRelation('workspace');

            self::assertInstanceOf(ParentedTenant::class, $workspace);
            self::assertFalse($workspace->preventsLazyLoading);
        }

        $tenants = array_map(static fn (Principal $membership): mixed => $membership->getTenant()?->getTenantIdentifier(), $candidates);

        self::assertSame([$first->tenant_id, $second->tenant_id], $tenants);
    }

    /**
     * The tenant relation is the one each listed principal names, not the one
     * the query's model would: rows the application's `principals()` reads as
     * one model and hands back as another (`afterQuery()`) have the listed
     * model's own relation loaded, under the name its `getTenantRelationName()`
     * gives.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRelationIsTheOneEachListedPrincipalNames(): void
    {
        $tenant = ParentedTenant::query()->create(['is_active' => true]);

        ChoosingMembership::query()->create(['identity_id' => 1, 'tenant_id' => $tenant->getKey()]);
        ChoosingMembership::query()->create(['identity_id' => 1, 'tenant_id' => $tenant->getKey()]);

        $query = ChoosingMembership::query()->orderBy('id')->afterQuery(static fn (Collection $rows): Collection => $rows->map(
            static fn (Model $row): Model => (new WorkspaceMembership)->newFromBuilder($row->getAttributes()),
        ));

        $listing    = PrincipalListing::of($this->identityListing($query));
        $candidates = self::principalsOf($listing);

        self::assertSame([null, null], $listing->refusals(self::GUARD, $candidates));

        foreach ($candidates as $candidate) {

            self::assertInstanceOf(WorkspaceMembership::class, $candidate);
            self::assertFalse($candidate->relationLoaded('tenant'));
            self::assertIsModel($tenant, $candidate->getRelation('workspace'));
        }
    }

    /**
     * Principals of several classes have their tenants read in one query per
     * class, each by the relation its own class defines, even when two classes
     * give the relation the same name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPrincipalsOfEachClassHaveTheirTenantsReadTogether(): void
    {
        [, $memberships] = $this->seedChooser(2);

        $workspace = ParentedTenant::query()->create(['is_active' => true]);
        $others    = [
            MorphTenantMembership::query()->create(['identity_id' => 1, 'tenant_type' => ParentedTenant::class, 'tenant_id' => $workspace->getKey()]),
            WorkspaceMembership::query()->create(['identity_id' => 1, 'tenant_id' => $workspace->getKey()]),
            WorkspaceMembership::query()->create(['identity_id' => 1, 'tenant_id' => $workspace->getKey()]),
        ];

        $candidates = [...$memberships, ...$others];
        $listing    = PrincipalListing::of($this->identityListing($this->builderListing($candidates)));
        $refusals   = null;
        $queries    = $this->queries(static function () use ($listing, $candidates, &$refusals): void {
            $refusals = $listing->refusals(self::GUARD, $candidates);
        });

        self::assertSame([null, null, null, null, null], $refusals);
        self::assertCount(3, $queries);
        self::assertInstanceOf(ActivatableTenant::class, $memberships[1]->getRelation('tenant'));
        self::assertInstanceOf(ParentedTenant::class, $others[0]->getRelation('tenant'));
        self::assertInstanceOf(ParentedTenant::class, $others[2]->getRelation('workspace'));
    }

    /**
     * Principals of one class on two connections have their tenants read on
     * each one's own connection: a tenant key that names an active tenant on
     * one and a deactivated tenant on the other is judged as each principal's
     * own connection stores it, whichever principal is listed first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPrincipalsOnEachConnectionHaveTheirTenantsReadOnIt(): void
    {
        [, [$membership]] = $this->seedChooser(1);

        config()->set('database.connections.' . self::ELSEWHERE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        $schema = Schema::connection(self::ELSEWHERE);

        $schema->create('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        $schema->create('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });

        ActivatableTenant::on(self::ELSEWHERE)->create(['id' => $membership->tenant_id, 'name' => 'Elsewhere', 'is_active' => false]);

        $elsewhere = ChoosingMembership::on(self::ELSEWHERE)->create(['identity_id' => $membership->identity_id, 'tenant_id' => $membership->tenant_id]);

        foreach ([[$membership, $elsewhere], [$elsewhere, $membership]] as $candidates) {

            $listing  = PrincipalListing::of($this->identityListing($this->builderListing($candidates)));
            $expected = array_map(static fn (ChoosingMembership $candidate): ?FailureReason => $candidate === $elsewhere ? FailureReason::TENANT_INACTIVE : null, $candidates);

            self::assertSame($expected, $listing->refusals(self::GUARD, $candidates));

            foreach ($candidates as $candidate) {

                $tenant = $candidate->getRelation('tenant');

                self::assertInstanceOf(ActivatableTenant::class, $tenant);
                self::assertSame($candidate->getConnectionName(), $tenant->getConnectionName());
            }
        }
    }

    /**
     * A polymorphic tenant relation is read once for the type the principals
     * name; a principal whose key is set without a type cannot say which tenant
     * it acts within and is refused as `tenant_inactive`, as when its tenant
     * was read on its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolymorphicTenantIsReadForItsTypeAndOneWithoutATypeRefused(): void
    {
        $active   = ActivatableTenant::query()->create(['name' => 'Active', 'is_active' => true]);
        $inactive = ActivatableTenant::query()->create(['name' => 'Inactive', 'is_active' => false]);

        foreach ([[ActivatableTenant::class, $active], [ActivatableTenant::class, $inactive], [null, $active]] as [$type, $tenant]) {
            MorphTenantMembership::query()->create(['identity_id' => 1, 'tenant_type' => $type, 'tenant_id' => $tenant->getKey()]);
        }

        $listing    = PrincipalListing::of($this->identityListing(MorphTenantMembership::query()->orderBy('id')));
        $candidates = self::principalsOf($listing);
        $refusals   = null;
        $queries    = $this->queries(static function () use ($listing, $candidates, &$refusals): void {
            $refusals = $listing->refusals(self::GUARD, $candidates);
        });

        self::assertSame([null, FailureReason::TENANT_INACTIVE, FailureReason::TENANT_INACTIVE], $refusals);
        self::assertCount(1, $queries);
    }

    /**
     * Rows of an application's eager load of the tenant relation (one that
     * reads soft-deleted tenants, one that hides active ones, one that selects
     * no activity column), whether the tenant is soft-deleted, and the refusal
     * the tenant as stored gives.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideApplicationEagerLoads(): iterable
    {
        yield 'one that reads soft-deleted tenants' => ['trashed', true, FailureReason::TENANT_INACTIVE];
        yield 'one that hides active tenants' => ['inactive', false, null];
        yield 'one that selects no activity column' => ['partial', false, null];
    }

    /**
     * Whatever the application's `principals()` eager-loaded under the tenant
     * relation's name, through its own `with()` or through a global scope that
     * runs after any the package could add, is replaced by the relation as a
     * lazy load reads it: a soft-deleted tenant is not loaded, an active one
     * is, and its activity column is.
     *
     * @param  string  $eagerLoad
     * @param  bool  $softDeleted
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $refusal
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideApplicationEagerLoads')]
    public function testWhatTheApplicationLoadedUnderTheNameIsReplaced(string $eagerLoad, bool $softDeleted, ?FailureReason $refusal): void
    {
        [$member, [$membership]] = $this->seedChooser(1);

        if ($softDeleted) {
            ActivatableTenant::query()->whereKey($membership->tenant_id)->delete();
        }

        $constraint = match ($eagerLoad) {
            'trashed'  => static fn (Relation $relation): Relation => $relation->withoutGlobalScope(SoftDeletingScope::class),
            'inactive' => static fn (Relation $relation): Relation => $relation->where('is_active', false),
            default    => static fn (Relation $relation): Relation => $relation->select(['id', 'name']),
        };

        $scope   = static fn (EloquentBuilder $query): EloquentBuilder => $query->with(['tenant' => $constraint]);
        $queries = [
            'with()'         => ChoosingMembership::query()->where('identity_id', $member->getKey())->with(['tenant' => $constraint]),
            'a global scope' => ChoosingMembership::query()->where('identity_id', $member->getKey())->withGlobalScope('tenant', $scope),
        ];

        foreach ($queries as $through => $query) {

            $listing = PrincipalListing::of($this->identityListing($query));

            self::assertSame([$refusal], $listing->refusals(self::GUARD, self::principalsOf($listing)), $through);
        }
    }

    /**
     * The placeholder a `withDefault()` relation loads for a missing tenant
     * stands for a tenant that cannot be loaded, refused as `tenant_inactive`
     * once each principal's tenant is looked for alone as well: the load's
     * query, then one for each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlaceholderForAMissingTenantIsRefused(): void
    {
        $tenant = ActivatableTenant::query()->create(['name' => 'Gone', 'is_active' => true]);

        DefaultTenantMembership::query()->create(['identity_id' => 1, 'tenant_id' => $tenant->getKey()]);
        DefaultTenantMembership::query()->create(['identity_id' => 1, 'tenant_id' => $tenant->getKey()]);

        $tenant->forceDelete();

        $listing    = PrincipalListing::of($this->identityListing(DefaultTenantMembership::query()->orderBy('id')));
        $candidates = self::principalsOf($listing);
        $refusals   = null;
        $queries    = $this->queries(static function () use ($listing, $candidates, &$refusals): void {
            $refusals = $listing->refusals(self::GUARD, $candidates);
        });

        self::assertSame([FailureReason::TENANT_INACTIVE, FailureReason::TENANT_INACTIVE], $refusals);
        self::assertCount(3, $queries);
    }

    /**
     * A tenant the load misses, through a key the database matches but PHP's
     * pairing does not (`'01'` against `1`), is read alone, as a lazy load
     * reads it, rather than taken for none: each principal holds its own
     * tenant, which does not opt into activation and so would otherwise read as
     * acting within no tenant, and one without a tenant key costs no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantTheLoadMissesIsReadAlone(): void
    {
        $membership = new class extends Model implements Principal {
            use ActsAsPrincipal;

            /** @var string|null The table associated with the model. */
            protected $table = 'keyed_memberships';

            /** @var array<string> The attributes that aren't mass assignable. */
            protected $guarded = [];

            /**
             * Acting tenant relation.
             *
             * @formatter:off
             *
             * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\TypedTenant, covariant $this>
             *
             * @formatter:on
             */
            public function tenant(): BelongsTo
            {
                return $this->belongsTo(TypedTenant::class, 'tenant_id');
            }
        };

        $this->assertMissedTenantsAreReadAlone($membership, null);
    }

    /**
     * A polymorphic tenant the load misses is read alone for its type, as a
     * lazy load reads it, rather than taken for none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolymorphicTenantTheLoadMissesIsReadAlone(): void
    {
        $membership = new class extends Model implements Principal {
            use ActsAsPrincipal;

            /** @var string|null The table associated with the model. */
            protected $table = 'keyed_memberships';

            /** @var array<string> The attributes that aren't mass assignable. */
            protected $guarded = [];

            /**
             * Acting tenant relation, typed by `tenant_type`.
             *
             * @formatter:off
             *
             * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, covariant $this>
             *
             * @formatter:on
             */
            public function tenant(): MorphTo
            {
                return $this->morphTo();
            }
        };

        $this->assertMissedTenantsAreReadAlone($membership, TypedTenant::class);
    }

    /**
     * A principal listed without its tenant key cannot say which tenant it acts
     * within, so judging it fails loudly rather than reading as acting within
     * none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalListedWithoutItsTenantKeyFailsLoudly(): void
    {
        [$member] = $this->seedChooser(2);

        $listing = PrincipalListing::of($this->identityListing(ChoosingMembership::query()->where('identity_id', $member->getKey())->select(['id', 'identity_id'])));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `tenant_id` attribute is not loaded');

        $listing->refusals(self::GUARD, self::principalsOf($listing));
    }

    /**
     * Nothing is loaded for a principal the package cannot know the tenant
     * relation of: one without a tenant relation, one that implements the
     * contract itself, and one that is no model. Each is judged as before: the
     * one that reads its own relation reads it on its stored copy. The
     * principals listed after them whose relation is known still have their
     * tenants read together.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingIsLoadedForAPrincipalWhoseTenantRelationIsUnknown(): void
    {
        [$member, $memberships] = $this->seedChooser(2);

        $custom = CustomTenantMembership::query()->whereKey($memberships[0]->getKey())->firstOrFail();
        $plain  = new PlainPrincipalFixture('plain');
        $bare   = new class extends Model implements Principal {
            use ActsAsPrincipal;
        };

        $candidates = [$custom, $plain, $bare, ...$memberships];
        $listing    = PrincipalListing::of($this->identityListing($this->builderListing($candidates)));
        $refusals   = null;
        $queries    = $this->queries(static function () use ($listing, $candidates, &$refusals): void {
            $refusals = $listing->refusals(self::GUARD, $candidates);
        });

        self::assertSame([null, null, null, null, null], $refusals);
        self::assertCount(2, $queries);
        self::assertStringContainsString(self::wrapped('activatable_tenants'), $queries[0]);
        self::assertStringContainsString(self::wrapped('activatable_tenants'), $queries[1]);
        self::assertFalse($custom->relationLoaded('tenant'));
        self::assertSame($member->getKey(), $custom->getIdentity()->getAuthIdentifier());
        self::assertSame(array_map(static fn (ChoosingMembership $membership): int => $membership->tenant_id, $memberships), array_map(self::tenantKeyOf(...), $memberships));
    }

    /**
     * An inactive principal is refused without its tenant being read, as when
     * each principal was judged alone: one whose polymorphic type names a
     * tenant class that no longer exists is refused as `principal_inactive` and
     * the others are judged, only the active ones' tenants loaded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactivePrincipalIsRefusedWithoutItsTenantBeingRead(): void
    {
        $tenant     = ActivatableTenant::query()->create(['name' => 'Kept', 'is_active' => true]);
        $membership = new class extends Model implements CanBeActive, Principal {
            use ActsAsPrincipal, ProvidesActiveState;

            /** @var string|null The table associated with the model. */
            protected $table = 'morph_tenant_memberships';

            /** @var array<string> The attributes that aren't mass assignable. */
            protected $guarded = [];

            /**
             * Acting tenant relation, typed by `tenant_type`.
             *
             * @formatter:off
             *
             * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, covariant $this>
             *
             * @formatter:on
             */
            public function tenant(): MorphTo
            {
                return $this->morphTo();
            }
        };

        $membership->newQuery()->create(['identity_id' => 1, 'tenant_type' => 'Tests\Retired\Tenant', 'tenant_id' => $tenant->getKey(), 'is_active' => false]);
        $membership->newQuery()->create(['identity_id' => 1, 'tenant_type' => ActivatableTenant::class, 'tenant_id' => $tenant->getKey(), 'is_active' => true]);

        $listing    = PrincipalListing::of($this->identityListing($membership->newQuery()->orderBy('id')));
        $candidates = self::principalsOf($listing);
        $refusals   = null;
        $queries    = $this->queries(static function () use ($listing, $candidates, &$refusals): void {
            $refusals = $listing->refusals(self::GUARD, $candidates);
        });

        self::assertSame([FailureReason::PRINCIPAL_INACTIVE, null], $refusals);
        self::assertCount(1, $queries);
        self::assertSame([false, true], array_map(self::tenantLoadedOn(...), $candidates));
    }

    /**
     * A listing of the resolver's default principal loads nothing and carries
     * no relation the resolver set: the tenant as stored decides, whether the
     * one planted reads active or inactive.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResolvedPrincipalCarriesNoRelationTheResolverSet(): void
    {
        [, [$membership]] = $this->seedChooser(1);

        $planted = ActivatableTenant::query()->findOrFail($membership->tenant_id);

        ActivatableTenant::query()->whereKey($membership->tenant_id)->update(['is_active' => false]);

        $membership->setRelation('tenant', $planted);

        self::assertSame([$membership], PrincipalListing::resolved($membership)->candidates);
        self::assertSame([FailureReason::TENANT_INACTIVE], PrincipalListing::resolved($membership)->refusals(self::GUARD, [$membership]));
        self::assertSame($planted, $membership->getRelation('tenant'));

        ActivatableTenant::query()->whereKey($membership->tenant_id)->update(['is_active' => true]);

        $membership->setRelation('tenant', ActivatableTenant::query()->findOrFail($membership->tenant_id)->forceFill(['is_active' => false]));

        self::assertSame([null], PrincipalListing::resolved($membership)->refusals(self::GUARD, [$membership]));
        self::assertSame([null], PrincipalListing::resolved(null)->candidates);
    }

    /**
     * Assert that, of three principals of the membership's class listed under
     * strict mode, the one whose key the load misses has its tenant read alone,
     * the one the load matches does not, and the one without a tenant key costs
     * no query; each then answers `getTenant()` with the tenant its key names,
     * without a further query.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Principal  $membership
     * @param  ?string  $type
     * @return void
     *
     * @throws \Throwable
     */
    private function assertMissedTenantsAreReadAlone(Model&Principal $membership, ?string $type): void
    {
        $missed  = TypedTenant::query()->create()->getKey();
        $matched = TypedTenant::query()->create()->getKey();

        self::assertIsInt($missed);
        self::assertIsInt($matched);

        foreach (['0' . $missed, (string) $matched, null] as $key) {
            $membership->newQuery()->create(['identity_id' => 1, 'tenant_type' => $key === null ? null : $type, 'tenant_id' => $key]);
        }

        Model::preventLazyLoading();

        $listing    = PrincipalListing::of($this->identityListing($membership->newQuery()->orderBy('id')));
        $candidates = self::principalsOf($listing);
        $refusals   = null;
        $queries    = $this->queries(static function () use ($listing, $candidates, &$refusals): void {
            $refusals = $listing->refusals(self::GUARD, $candidates);
        });

        self::assertSame([null, null, null], $refusals);
        self::assertCount(2, $queries);
        self::assertStringContainsString(self::wrapped('typed_tenants'), $queries[1]);

        $tenants = null;

        self::assertSame([], $this->queries(static function () use ($candidates, &$tenants): void {
            $tenants = array_map(static fn (Principal $candidate): mixed => $candidate->getTenant()?->getTenantIdentifier(), $candidates);
        }));

        self::assertSame([$missed, $matched, null], $tenants);
    }

    /**
     * Persist a chooser with the given number of memberships, each in an active
     * tenant of its own.
     *
     * @param  int  $count
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: list<\Tests\Integration\Fixtures\ChoosingMembership>}
     */
    private function seedChooser(int $count): array
    {
        $member      = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (range(1, $count) as $index) {
            $tenant = ActivatableTenant::query()->create(['name' => 'Tenant ' . $index, 'is_active' => true]);

            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        return [$member, $memberships];
    }

    /**
     * An identity whose `principals()` is the query.
     *
     * @param  \Illuminate\Contracts\Database\Eloquent\Builder  $query
     * @return \SineMacula\Laravel\Authentication\Contracts\HasPrincipals&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identityListing(Builder $query): HasPrincipals&Identity
    {
        $identity = \Mockery::mock(Identity::class, HasPrincipals::class);

        $identity->shouldReceive('principals')->andReturn($query);

        return $identity;
    }

    /**
     * A builder whose read returns the given principals, as they are.
     *
     * @param  list<mixed>  $principals
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>
     */
    private function builderListing(array $principals): EloquentBuilder
    {
        $query = \Mockery::mock(EloquentBuilder::class);

        $query->shouldReceive('useWritePdo')->andReturnSelf();
        $query->shouldReceive('get')->andReturn(Collection::make($principals));

        return $query;
    }

    /**
     * The SQL of every query the callback runs.
     *
     * @param  \Closure(): void  $callback
     * @return list<string>
     */
    private function queries(\Closure $callback): array
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        try {
            $callback();
        } finally {
            DB::disableQueryLog();
        }

        return array_map(static fn (array $query): string => $query['query'], DB::getQueryLog());
    }

    /**
     * The table's name as the default connection's grammar quotes it in SQL.
     *
     * @param  string  $table
     * @return string
     */
    private static function wrapped(string $table): string
    {
        return DB::connection()->getQueryGrammar()->wrapTable($table);
    }

    /**
     * The listing's candidates, each a principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\PrincipalListing  $listing
     * @return list<\SineMacula\Laravel\Authentication\Contracts\Principal>
     */
    private static function principalsOf(PrincipalListing $listing): array
    {
        return array_values(array_filter($listing->candidates, static fn (mixed $candidate): bool => $candidate instanceof Principal));
    }

    /**
     * Whether the principal, an Eloquent model, holds its tenant loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    private static function tenantLoadedOn(Principal $principal): bool
    {
        self::assertInstanceOf(Model::class, $principal);

        return $principal->relationLoaded('tenant');
    }

    /**
     * The key of the tenant the principal holds loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return mixed
     */
    private static function tenantKeyOf(Principal $principal): mixed
    {
        self::assertInstanceOf(Model::class, $principal);
        self::assertTrue($principal->relationLoaded('tenant'));

        $tenant = $principal->getRelation('tenant');

        self::assertInstanceOf(Model::class, $tenant);

        return $tenant->getKey();
    }
}
