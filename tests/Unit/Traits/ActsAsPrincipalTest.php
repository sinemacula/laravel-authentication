<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Database\Eloquent\Relations\Relation;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversTrait;
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
     * Trait returns the tenant relation when it implements Tenant.
     *
     * @return void
     */
    public function testGetTenantReturnsRelatedTenant(): void
    {
        $tenant = \Mockery::mock(Tenant::class);

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
        $tenant = \Mockery::mock(Tenant::class);

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
