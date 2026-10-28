<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\Relations\Relation;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use Tests\Unit\Stubs\Stub3dPrincipal;
use Tests\Unit\Stubs\Stub3dPrincipalWithOwnerRelation;
use Tests\Unit\Stubs\StubActivatableTenant;
use Tests\Unit\Stubs\StubModel;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubTenant;

/**
 * Unit tests for the ActsAsPrincipal trait.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[CoversTrait(ActsAsPrincipal::class)]
final class ActsAsPrincipalTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Trait returns the configured id attribute as the principal identifier.
     *
     * @return void
     */
    public function testGetPrincipalIdentifierReturnsIdAttribute(): void
    {
        $principal = new Stub3dPrincipal;
        $principal->setAttribute('id', 42);

        self::assertSame(42, $principal->getPrincipalIdentifier());
    }

    /**
     * Trait returns the identity relation when it implements Identity.
     *
     * @return void
     */
    public function testGetIdentityReturnsRelatedIdentity(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $principal = new Stub3dPrincipal;
        $principal->setRelation('identity', $identity);

        self::assertSame($identity, $principal->getIdentity());
    }

    /**
     * Trait short-circuits to the principal itself when the model implements
     * `Identity` (2D mode), so the `identity` relation is never queried.
     *
     * @return void
     */
    public function testGetIdentityReturnsSelfWhen2dIdentity(): void
    {
        $principal = new StubPrincipal;

        self::assertSame($principal, $principal->getIdentity());
    }

    /**
     * Trait throws LogicException when the identity relation is absent.
     *
     * @return void
     */
    public function testGetIdentityThrowsLogicExceptionWhenRelationMissing(): void
    {
        $principal = new Stub3dPrincipal;
        $principal->setRelation('identity', null);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('expected its identity relation `identity` to return an Identity instance');

        $principal->getIdentity();
    }

    /**
     * Trait honours an `identityRelationName` override declared on the
     * principal subclass and reads the identity from the renamed relation slot.
     *
     * @return void
     */
    public function testGetIdentityHonoursIdentityRelationNameOverride(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $principal = new Stub3dPrincipalWithOwnerRelation;
        $principal->setRelation('owner', $identity);

        self::assertSame($identity, $principal->getIdentity());
    }

    /**
     * A persisted principal with no identity relation throws the trait's own
     * `LogicException` under Eloquent's strict missing-attribute mode, rather
     * than the `MissingAttributeException` reading the absent key would raise.
     *
     * @return void
     */
    public function testGetIdentityThrowsLogicExceptionWithoutIdentityRelationUnderStrictMode(): void
    {
        $principal         = new Stub3dPrincipal;
        $principal->exists = true;

        Model::preventAccessingMissingAttributes();

        try {
            $principal->getIdentity();

            self::fail('A principal without an identity relation should not report an owner.');
        } catch (\LogicException $exception) {
            self::assertSame(\LogicException::class, $exception::class);
            self::assertStringContainsString('expected its identity relation `identity` to return an Identity instance, got null', $exception->getMessage());
        } finally {
            Model::preventAccessingMissingAttributes(false);
        }
    }

    /**
     * An identity exposed through an attribute accessor rather than a relation
     * is still read.
     *
     * @return void
     */
    public function testGetIdentityReadsIdentityExposedThroughAttributeAccessor(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $principal = new class extends Stub3dPrincipal {
            /** @var ?\SineMacula\Laravel\Authentication\Contracts\Identity Identity returned by the accessor. */
            public ?Identity $accessorIdentity = null;

            /**
             * Expose the identity through an attribute accessor.
             *
             * @formatter:off
             *
             * @return \Illuminate\Database\Eloquent\Casts\Attribute<?\SineMacula\Laravel\Authentication\Contracts\Identity, never>
             *
             * @formatter:on
             */
            protected function identity(): Attribute
            {
                return Attribute::get(fn (): ?Identity => $this->accessorIdentity);
            }
        };

        $principal->accessorIdentity = $identity;

        self::assertSame($identity, $principal->getIdentity());
    }

    /**
     * An identity relation that has not been loaded yet is loaded and read.
     *
     * @return void
     */
    public function testGetIdentityLoadsAnIdentityRelationThatIsNotLoadedYet(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $relation = \Mockery::mock(BelongsTo::class);
        $relation->shouldReceive('getResults')->once()->andReturn($identity);

        // A subclass of its own, so the resolved relation stays off the shared
        // stub class.
        $principal = new class extends Stub3dPrincipal {};

        $principal::resolveRelationUsing('identity', static fn (): Relation => $relation);

        self::assertSame($identity, $principal->getIdentity());
    }

    /**
     * Trait returns the tenant relation when it implements Tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsRelatedTenant(): void
    {
        $tenant = $this->storedTenant();

        $principal = new Stub3dPrincipal;
        $principal->setRelation('tenant', $tenant);

        self::assertSame($tenant, $principal->getTenant());
    }

    /**
     * Trait returns null when the tenant relation is absent.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenAbsent(): void
    {
        $principal = new Stub3dPrincipal;
        $principal->setRelation('tenant', null);

        self::assertNull($principal->getTenant());
    }

    /**
     * A principal with no tenant relation, attribute, or loaded relation acts
     * within no tenant, and reading it does not trip Eloquent's strict
     * missing-attribute mode on a persisted model.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWithoutTenantRelationUnderStrictMode(): void
    {
        $principal         = new Stub3dPrincipal;
        $principal->exists = true;

        Model::preventAccessingMissingAttributes();

        try {
            self::assertNull($principal->getTenant());
        } finally {
            Model::preventAccessingMissingAttributes(false);
        }
    }

    /**
     * A tenant exposed through an attribute accessor rather than a relation is
     * still read.
     *
     * @return void
     */
    public function testGetTenantReadsTenantExposedThroughAttributeAccessor(): void
    {
        $tenant = $this->storedTenant();

        $principal = new class extends Stub3dPrincipal {
            /** @var ?\SineMacula\Laravel\Authentication\Contracts\Tenant Tenant returned by the accessor. */
            public ?Tenant $accessorTenant = null;

            /**
             * Expose the tenant through an attribute accessor.
             *
             * @formatter:off
             *
             * @return \Illuminate\Database\Eloquent\Casts\Attribute<?\SineMacula\Laravel\Authentication\Contracts\Tenant, never>
             *
             * @formatter:on
             */
            protected function tenant(): Attribute
            {
                return Attribute::get(fn (): ?Tenant => $this->accessorTenant);
            }
        };

        $principal->accessorTenant = $tenant;

        self::assertSame($tenant, $principal->getTenant());
    }

    /**
     * A principal whose `BelongsTo` tenant key names a tenant that opts into
     * activation (`Tenant` and `CanBeActive`) throws when that tenant cannot be
     * loaded (deleted, soft-deleted, or scoped out) instead of reading as no
     * tenant.
     *
     * @return void
     */
    public function testGetTenantThrowsWhenTheNamedActivatableTenantCannotBeLoaded(): void
    {
        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubActivatableTenant), ['tenant_id' => 5]);

        $this->expectException(TenantUnavailableException::class);
        $this->expectExceptionMessage('names a tenant through `tenant` that cannot be loaded');

        $principal->getTenant();
    }

    /**
     * A tenant that does not implement `CanBeActive` is never checked, so one
     * that cannot be loaded reads as no tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenANamedTenantThatDoesNotOptInCannotBeLoaded(): void
    {
        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubTenant), ['tenant_id' => 5]);

        self::assertNull($principal->getTenant());
    }

    /**
     * A relation to a model that implements `CanBeActive` but is not a `Tenant`
     * does not name a tenant, so a missing row reads as no tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenTheRelatedModelIsNotATenant(): void
    {
        $related = new class extends Model implements CanBeActive {
            /**
             * Report the model active.
             *
             * @return bool
             */
            #[\Override]
            public function isActive(): bool
            {
                return true;
            }
        };

        $principal = $this->principalWithTenantRelation($this->belongsTo($related), ['tenant_id' => 5]);

        self::assertNull($principal->getTenant());
    }

    /**
     * A principal whose `BelongsTo` key for an activatable tenant is not set
     * acts within no tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenTheTenantKeyIsNotSet(): void
    {
        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubActivatableTenant), ['tenant_id' => null]);

        self::assertNull($principal->getTenant());
    }

    /**
     * A principal loaded without the key of a tenant that opts into activation
     * (a partial select) is reported instead of being read as acting within no
     * tenant.
     *
     * @return void
     */
    public function testGetTenantThrowsWhenTheActivatableTenantKeyIsNotLoaded(): void
    {
        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubActivatableTenant), []);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('acts within: its `tenant_id` attribute is not loaded. Select the column so the tenant can be checked.');

        $principal->getTenant();
    }

    /**
     * Without the key of a tenant that does not opt in, the principal still
     * acts within no tenant: that tenant is never checked.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWithoutTheKeyOfATenantThatDoesNotOptIn(): void
    {
        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubTenant), []);

        self::assertNull($principal->getTenant());
    }

    /**
     * Only a `BelongsTo` key names a tenant: another relation that loads
     * nothing reads as no tenant, even when the key it would be read from is
     * set.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenAnotherRelationLoadsNothing(): void
    {
        $relation = \Mockery::mock(HasOne::class);
        $relation->shouldReceive('getRelated')->andReturn(new StubActivatableTenant);

        $principal = $this->principalWithTenantRelation($relation, ['tenant_id' => 5]);

        self::assertNull($principal->getTenant());
    }

    /**
     * A tenant relation that returns a model which is not a `Tenant` is not a
     * tenant at all: the principal acts within no tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenTheRelationReturnsAModelThatIsNotATenant(): void
    {
        $principal = new Stub3dPrincipal;
        $principal->setRelation('tenant', new StubModel);

        self::assertNull($principal->getTenant());
    }

    /**
     * The unsaved placeholder a `withDefault()` relation returns for a missing
     * row of a tenant that opts into activation is not a present tenant: with
     * the key set, the tenant cannot be loaded.
     *
     * @return void
     */
    public function testGetTenantThrowsForThePlaceholderOfAnActivatableTenantThatCannotBeLoaded(): void
    {
        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubActivatableTenant), ['tenant_id' => 5]);
        $principal->setRelation('tenant', new StubActivatableTenant);

        $this->expectException(TenantUnavailableException::class);
        $this->expectExceptionMessage('names a tenant through `tenant` that cannot be loaded');

        $principal->getTenant();
    }

    /**
     * Without a key, the placeholder of a tenant that opts into activation
     * reads as no tenant rather than as a present tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsNullForThePlaceholderOfAnActivatableTenantWithoutAKey(): void
    {
        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubActivatableTenant), ['tenant_id' => null]);
        $principal->setRelation('tenant', new StubActivatableTenant);

        self::assertNull($principal->getTenant());
    }

    /**
     * A stored tenant that opts into activation is returned as loaded.
     *
     * @return void
     */
    public function testGetTenantReturnsAStoredActivatableTenant(): void
    {
        $tenant         = new StubActivatableTenant;
        $tenant->exists = true;

        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubActivatableTenant), ['tenant_id' => 5]);
        $principal->setRelation('tenant', $tenant);

        self::assertSame($tenant, $principal->getTenant());
    }

    /**
     * A tenant that is not an Eloquent model (a custom `Tenant`) is never a
     * placeholder, even on a relation to a tenant that opts into activation:
     * only an unsaved model stands in for a missing row.
     *
     * @return void
     */
    public function testGetTenantReturnsATenantThatIsNotAModelOnAnActivatableRelation(): void
    {
        $tenant = new class implements Tenant {
            /** @var bool Looks like an unsaved model's flag, but the tenant is not a model. */
            public bool $exists = false;

            /**
             * Return the tenant's identifier.
             *
             * @return mixed
             */
            #[\Override]
            public function getTenantIdentifier(): mixed
            {
                return 5;
            }
        };

        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubActivatableTenant), ['tenant_id' => 5]);
        $principal->setRelation('tenant', $tenant);

        self::assertSame($tenant, $principal->getTenant());
    }

    /**
     * The placeholder of a tenant that does not opt into activation is still
     * returned: that tenant is never checked.
     *
     * @return void
     */
    public function testGetTenantReturnsThePlaceholderOfATenantThatDoesNotOptIn(): void
    {
        $placeholder = new StubTenant;

        $principal = $this->principalWithTenantRelation($this->belongsTo(new StubTenant), ['tenant_id' => 5]);
        $principal->setRelation('tenant', $placeholder);

        self::assertSame($placeholder, $principal->getTenant());
    }

    /**
     * A principal loaded without the type column of a polymorphic tenant
     * relation is reported: without the type, the tenant cannot be told apart
     * from one that opts into activation.
     *
     * @return void
     */
    public function testGetTenantThrowsWhenTheMorphTypeIsNotLoaded(): void
    {
        $principal = $this->principalWithTenantRelation($this->morphTo(new Stub3dPrincipal), ['tenant_id' => 5]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('acts within: its `tenant_type` attribute is not loaded. Select the column so the tenant can be checked.');

        $principal->getTenant();
    }

    /**
     * Rows of `[type]`: the empty values of a polymorphic type column.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideEmptyMorphTypes(): iterable
    {
        yield from [
            'null'         => [null],
            'empty string' => [''],
        ];
    }

    /**
     * A polymorphic tenant whose key is set but whose type is empty names a
     * tenant that cannot be loaded.
     *
     * @param  ?string  $type
     * @return void
     */
    #[DataProvider('provideEmptyMorphTypes')]
    public function testGetTenantThrowsWhenTheMorphTypeIsEmptyAndTheKeyIsSet(?string $type): void
    {
        $principal = $this->principalWithTenantRelation($this->morphTo(new Stub3dPrincipal), ['tenant_type' => $type, 'tenant_id' => 5]);

        $this->expectException(TenantUnavailableException::class);
        $this->expectExceptionMessage('names a tenant through `tenant` without its `tenant_type` type, so it cannot be loaded.');

        $principal->getTenant();
    }

    /**
     * Rows of `[attributes, exception]`: polymorphic tenants that cannot say
     * which model they name, and what reports them.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: class-string<\Throwable>}>
     */
    public static function provideMorphTenantsThatCannotNameTheirModel(): iterable
    {
        yield from [
            'type not loaded'     => [['tenant_id' => 5], \LogicException::class],
            'type empty, key set' => [['tenant_type' => '', 'tenant_id' => 5], TenantUnavailableException::class],
        ];
    }

    /**
     * A polymorphic tenant that cannot say which model it names is reported
     * before its relation is lazy-loaded: Eloquent would build that load
     * against the principal's own model with an empty type column, which
     * PostgreSQL and MySQL reject.
     *
     * @param  array<string, mixed>  $attributes
     * @param  class-string<\Throwable>  $exception
     * @return void
     */
    #[DataProvider('provideMorphTenantsThatCannotNameTheirModel')]
    public function testGetTenantReportsAMorphTenantThatCannotNameItsModelBeforeLoadingIt(array $attributes, string $exception): void
    {
        $relation = $this->morphTo(new Stub3dPrincipal);
        $relation->shouldNotReceive('getResults');

        $principal = $this->principalWithTenantRelation($relation, $attributes);
        $principal->unsetRelation('tenant');

        $this->expectException($exception);

        $principal->getTenant();
    }

    /**
     * A polymorphic tenant with an empty type and an empty key names no tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenTheMorphTypeAndKeyAreEmpty(): void
    {
        $principal = $this->principalWithTenantRelation($this->morphTo(new Stub3dPrincipal), ['tenant_type' => null, 'tenant_id' => null]);

        self::assertNull($principal->getTenant());
    }

    /**
     * A polymorphic tenant with an empty type, loaded without its key, is
     * reported rather than read as naming no tenant.
     *
     * @return void
     */
    public function testGetTenantThrowsWhenTheMorphTypeIsEmptyAndTheKeyIsNotLoaded(): void
    {
        $principal = $this->principalWithTenantRelation($this->morphTo(new Stub3dPrincipal), ['tenant_type' => null]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('acts within: its `tenant_id` attribute is not loaded.');

        $principal->getTenant();
    }

    /**
     * A polymorphic tenant whose type names a tenant that opts into activation
     * is checked like a `BelongsTo` one: a set key that loads nothing cannot be
     * loaded.
     *
     * @return void
     */
    public function testGetTenantThrowsWhenTheMorphTypeNamesAnActivatableTenantThatCannotBeLoaded(): void
    {
        $principal = $this->principalWithTenantRelation($this->morphTo(new StubActivatableTenant), ['tenant_type' => StubActivatableTenant::class, 'tenant_id' => 5]);

        $this->expectException(TenantUnavailableException::class);
        $this->expectExceptionMessage('names a tenant through `tenant` that cannot be loaded');

        $principal->getTenant();
    }

    /**
     * A polymorphic tenant whose type names a tenant that does not opt in is
     * never checked, so one that cannot be loaded reads as no tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsNullWhenTheMorphTypeNamesATenantThatDoesNotOptIn(): void
    {
        $principal = $this->principalWithTenantRelation($this->morphTo(new StubTenant), ['tenant_type' => StubTenant::class, 'tenant_id' => 5]);

        self::assertNull($principal->getTenant());
    }

    /**
     * Build a `BelongsTo` relation double whose related model is the supplied
     * model.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $related
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>&\Mockery\MockInterface
     */
    private function belongsTo(Model $related): BelongsTo
    {
        $relation = \Mockery::mock(BelongsTo::class);
        $relation->shouldReceive('getRelated')->andReturn($related);

        return $relation;
    }

    /**
     * Build a tenant model that reads as stored.
     *
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private function storedTenant(): StubTenant
    {
        $tenant         = new StubTenant;
        $tenant->exists = true;

        return $tenant;
    }

    /**
     * Build a `MorphTo` relation double typed by `tenant_type` whose related
     * model is the supplied model (the principal's own model when the type is
     * empty, as Eloquent builds it).
     *
     * @param  \Illuminate\Database\Eloquent\Model  $related
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>&\Mockery\MockInterface
     */
    private function morphTo(Model $related): MorphTo
    {
        $relation = \Mockery::mock(MorphTo::class);
        $relation->shouldReceive('getMorphType')->andReturn('tenant_type');
        $relation->shouldReceive('getRelated')->andReturn($related);

        return $relation;
    }

    /**
     * Build a principal whose `tenant` relation is the supplied relation double
     * keyed on `tenant_id`, with the tenant relation loaded as empty.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Relations\Relation<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model, mixed>&\Mockery\MockInterface  $relation
     * @param  array<string, mixed>  $attributes
     * @return \Tests\Unit\Stubs\Stub3dPrincipal
     *
     * @formatter:on
     */
    private function principalWithTenantRelation(Relation $relation, array $attributes): Stub3dPrincipal
    {
        $relation->shouldReceive('getForeignKeyName')->andReturn('tenant_id');

        // A subclass of its own, so the resolved relation stays off the shared
        // stub class.
        $principal = new class extends Stub3dPrincipal {};

        $principal::resolveRelationUsing('tenant', static fn (): Relation => $relation);

        $principal->forceFill($attributes);
        $principal->setRelation('tenant', null);

        return $principal;
    }
}
