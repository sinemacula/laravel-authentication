<?php

declare(strict_types = 1);

namespace Tests\Feature\Events\Concerns;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\Concerns\SerializesLiveModels;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Feature tests for the live models of an event crossing a queue: an Eloquent
 * model is fetched again in its state then, with the relations it had loaded,
 * or comes back `null` once its row is gone, so the event always restores with
 * its snapshot; a part that is not an Eloquent model does not cross; a database
 * error still surfaces.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
#[CoversClass(PrincipalSwitched::class)]
#[CoversTrait(SerializesLiveModels::class)]
final class SerializesLiveModelsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Tests\Integration\Fixtures\ActivatableTenantMember The member the context is about. */
    private ActivatableTenantMember $member;

    /** @var \Tests\Integration\Fixtures\ActivatableTenantMembership The membership the member acts as. */
    private ActivatableTenantMembership $membership;

    /** @var \Tests\Integration\Fixtures\ActivatableTenant The tenant the membership acts within. */
    private ActivatableTenant $tenant;

    /**
     * Create the tables and seed a member.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        [$this->member, $this->membership, $this->tenant] = $this->seedMember();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A live model is fetched again when the context is restored, as a new
     * instance in its state then, with the relations it had loaded.
     *
     * @return void
     */
    public function testALiveModelIsFetchedAgainInItsStateThen(): void
    {
        $this->membership->load('tenant');

        $queued = serialize($this->context());

        ActivatableTenantMember::query()->update(['email' => 'renamed@example.test']);
        ActivatableTenant::query()->update(['name' => 'Renamed']);

        $copy = unserialize($queued);

        self::assertInstanceOf(EventContext::class, $copy);
        self::assertInstanceOf(ActivatableTenantMember::class, $copy->identity);
        self::assertNotSame($this->member, $copy->identity);
        self::assertTrue($this->member->is($copy->identity));
        self::assertSame('renamed@example.test', $copy->identity->email);
        self::assertInstanceOf(ActivatableTenantMembership::class, $copy->principal);
        self::assertTrue($copy->principal->relationLoaded('tenant'));
        self::assertSame('Renamed', $copy->principal->tenant?->name);
        self::assertInstanceOf(ActivatableTenant::class, $copy->tenant);
        self::assertSame('Renamed', $copy->tenant->name);
        self::assertSame('device-1', $copy->deviceId);
    }

    /**
     * A live model whose row is gone comes back `null` rather than failing the
     * restore, and the snapshot names it as it was; a soft-deleted row is still
     * there, so it is restored, trashed, as Laravel restores a queued model.
     *
     * @return void
     */
    public function testALiveModelWhoseRowIsGoneComesBackNull(): void
    {
        $context = $this->context();
        $queued  = serialize($context);

        ActivatableTenantMembership::query()->delete();
        ActivatableTenantMember::query()->delete();
        $this->tenant->delete();

        $copy = unserialize($queued);

        self::assertInstanceOf(EventContext::class, $copy);
        self::assertNull($copy->identity);
        self::assertNull($copy->principal);
        self::assertInstanceOf(ActivatableTenant::class, $copy->tenant);
        self::assertTrue($copy->tenant->trashed());
        self::assertSame($context->toArray(), $copy->toArray());
        self::assertSame(ActivatableTenantMember::class, $copy->identityMorphClass);
        self::assertSame((string) $this->member->getKey(), $copy->identityId); // @phpstan-ignore cast.string
    }

    /**
     * A live part that is not an Eloquent model, whichever part it is, does not
     * enter the payload and comes back `null`; the snapshot and the values
     * beside it cross as they are.
     *
     * @return void
     */
    public function testAPartThatIsNotAnEloquentModelDoesNotCross(): void
    {
        $parts = [
            new PlainIdentityFixture('plain-identity'),
            new PlainPrincipalFixture('plain-principal'),
            new PlainTenantFixture('plain-tenant'),
            new PlainDeviceFixture('plain-device'),
        ];

        $context = new EventContext('api', new ClientContext('203.0.113.7', 'agent'), ...$parts, method: 'password');
        $queued  = serialize($context);

        foreach ($parts as $part) {
            self::assertStringNotContainsString('O:' . strlen($part::class) . ':"' . $part::class . '"', $queued);
        }

        $copy = unserialize($queued);

        self::assertInstanceOf(EventContext::class, $copy);
        self::assertNull($copy->identity);
        self::assertNull($copy->principal);
        self::assertNull($copy->tenant);
        self::assertNull($copy->device);
        self::assertSame($context->toArray(), $copy->toArray());
        self::assertSame('plain-principal', $copy->principalId);
        self::assertSame('agent', $copy->client->userAgent);
    }

    /**
     * A database that cannot be read is not mistaken for a deleted row: the
     * restore fails with the database's error.
     *
     * @return void
     */
    public function testADatabaseErrorStillSurfaces(): void
    {
        $queued = serialize($this->context());

        Schema::drop('activatable_tenant_members');

        $this->expectException(QueryException::class);

        unserialize($queued);
    }

    /**
     * A switch's previous principal is a live model too: once its row is gone
     * it comes back `null`, and the recorded morph class and identifier name
     * it.
     *
     * @return void
     */
    public function testAPreviousPrincipalWhoseRowIsGoneComesBackNull(): void
    {
        $previous = ActivatableTenantMembership::query()->create(['identity_id' => $this->member->getKey(), 'tenant_id' => $this->tenant->getKey()]);
        $event    = new PrincipalSwitched($this->context(), $previous, $previous->getMorphClass(), (string) $previous->getKey()); // @phpstan-ignore cast.string

        $kept = unserialize(serialize($event));

        self::assertInstanceOf(PrincipalSwitched::class, $kept);
        self::assertTrue($previous->is($kept->previousPrincipal));
        self::assertNotSame($previous, $kept->previousPrincipal);

        $queued = serialize($event);

        $previous->delete();

        $copy = unserialize($queued);

        self::assertInstanceOf(PrincipalSwitched::class, $copy);
        self::assertNull($copy->previousPrincipal);
        self::assertSame(ActivatableTenantMembership::class, $copy->previousPrincipalMorphClass);
        self::assertSame((string) $previous->getKey(), $copy->previousPrincipalId); // @phpstan-ignore cast.string
        self::assertTrue($this->membership->is($copy->context->principal));
    }

    /**
     * A context of the seeded member, membership and tenant, with a named
     * device.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function context(): EventContext
    {
        return new EventContext('api', new ClientContext('203.0.113.7', 'agent'), $this->member, $this->membership, $this->tenant, method: 'password', deviceId: 'device-1');
    }
}
