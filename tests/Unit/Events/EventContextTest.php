<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubTenant;

/**
 * EventContext unit tests: the parts it keeps, the snapshot it takes when it is
 * built, and the snapshot as scalars.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
final class EventContextTest extends TestCase
{
    /**
     * Release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Every part given is kept as given.
     *
     * @return void
     */
    public function testKeepsEveryPart(): void
    {
        $client    = new ClientContext('203.0.113.7', 'agent');
        $identity  = new PlainIdentityFixture(7);
        $principal = new PlainPrincipalFixture('p-1');
        $tenant    = self::tenant(3);
        $device    = new PlainDeviceFixture('device-1');

        $context = new EventContext('api', $client, $identity, $principal, $tenant, $device, 'password');

        self::assertSame('api', $context->guard);
        self::assertSame($client, $context->client);
        self::assertSame($identity, $context->identity);
        self::assertSame($principal, $context->principal);
        self::assertSame($tenant, $context->tenant);
        self::assertSame($device, $context->device);
        self::assertSame('password', $context->method);
        self::assertNull($context->credentialId);
        self::assertNull($context->scopes);
    }

    /**
     * The credential's identifier and the scopes it grants are kept as given;
     * `[]` (a credential granting no scope) stays distinct from `null` (no
     * credential limit).
     *
     * @return void
     */
    public function testKeepsTheCredentialAndItsScopes(): void
    {
        $client = new ClientContext(null, null);

        $context = new EventContext('machine', $client, new PlainIdentityFixture(7), credentialId: 'key-1', scopes: ['invoices:read', 'invoices:write']);

        self::assertSame('key-1', $context->credentialId);
        self::assertSame(['invoices:read', 'invoices:write'], $context->scopes);

        $none = new EventContext('machine', $client, credentialId: 'key-2', scopes: []);

        self::assertSame([], $none->scopes);
    }

    /**
     * The context records when it was built, to the microsecond, as the clock
     * says then.
     *
     * @return void
     */
    public function testRecordsWhenItWasBuilt(): void
    {
        $now = CarbonImmutable::parse('2026-04-06 12:00:00.123456', 'UTC');

        CarbonImmutable::setTestNow($now);

        $context = new EventContext('api', new ClientContext(null, null));

        CarbonImmutable::setTestNow($now->addHour());

        self::assertTrue($now->equalTo($context->occurredAt));
        self::assertSame('123456', $context->occurredAt->format('u'));
    }

    /**
     * The identifiers are snapshotted as strings, and the identity, principal
     * and tenant by their class as well: the identity's auth identifier, the
     * principal's and the tenant's identifiers, and the device's.
     *
     * @return void
     */
    public function testSnapshotsEveryReferenceAsAString(): void
    {
        $client  = new ClientContext(null, null);
        $context = new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture(42), new PlainTenantFixture(3), new PlainDeviceFixture('device-1'));

        self::assertSame(PlainIdentityFixture::class, $context->identityMorphClass);
        self::assertSame('7', $context->identityId);
        self::assertSame(PlainPrincipalFixture::class, $context->principalMorphClass);
        self::assertSame('42', $context->principalId);
        self::assertSame(PlainTenantFixture::class, $context->tenantMorphClass);
        self::assertSame('3', $context->tenantId);
        self::assertSame('device-1', $context->deviceId);
    }

    /**
     * An Eloquent identity, principal or tenant is recorded by its morph class,
     * as a device row records a principal, not by its class name.
     *
     * @return void
     */
    public function testRecordsEloquentModelsByTheirMorphClass(): void
    {
        $principal = new class extends StubPrincipal {
            /**
             * Return the alias the morph map gives the model.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'member';
            }
        };

        $tenant = new class extends StubTenant {
            /**
             * Return the alias the morph map gives the model.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'workspace';
            }
        };

        $principal->forceFill(['id' => 9]);
        $tenant->forceFill(['id' => 4]);

        $context = new EventContext('api', new ClientContext(null, null), $principal, $principal, $tenant);

        self::assertSame('member', $context->identityMorphClass);
        self::assertSame('9', $context->identityId);
        self::assertSame('member', $context->principalMorphClass);
        self::assertSame('9', $context->principalId);
        self::assertSame('workspace', $context->tenantMorphClass);
        self::assertSame('4', $context->tenantId);
    }

    /**
     * The principal's categorical type is what `Auth::type()` reports, read
     * from what the context holds: the principal's own type, else its tenant's,
     * else none; an empty type reads as none, and without a principal there is
     * none to report, whatever the tenant's.
     *
     * @return void
     */
    public function testRecordsThePrincipalsCategoricalType(): void
    {
        $client = new ClientContext(null, null);

        self::assertSame('staff', (new EventContext('api', $client, principal: self::typedPrincipal('staff'), tenant: self::tenant(3, 'workspace')))->principalCategory);
        self::assertSame('workspace', (new EventContext('api', $client, principal: self::typedPrincipal(''), tenant: self::tenant(3, 'workspace')))->principalCategory);
        self::assertSame('workspace', (new EventContext('api', $client, principal: new PlainPrincipalFixture(1), tenant: self::tenant(3, 'workspace')))->principalCategory);
        self::assertNull((new EventContext('api', $client, principal: new PlainPrincipalFixture(1), tenant: self::tenant(3, '')))->principalCategory);
        self::assertNull((new EventContext('api', $client, principal: new PlainPrincipalFixture(1)))->principalCategory);
        self::assertNull((new EventContext('api', $client, tenant: self::tenant(3, 'workspace')))->principalCategory);
    }

    /**
     * A principal or tenant loaded without its type column has a type the
     * context cannot read without a query: it is recorded as unknown rather
     * than failing the flow that reports the event.
     *
     * @return void
     */
    public function testATypeLoadedWithoutItsColumnIsRecordedAsUnknown(): void
    {
        $context = new EventContext('api', new ClientContext(null, null), principal: new PlainPrincipalFixture(1), tenant: self::tenant(3));

        self::assertNull($context->principalCategory);
        self::assertSame('3', $context->tenantId);
    }

    /**
     * A context with nothing established keeps only the guard, the client and
     * the time, and every other snapshot is null.
     *
     * @return void
     */
    public function testUnknownPartsAreNull(): void
    {
        $context = new EventContext(null, new ClientContext(null, null));

        self::assertNull($context->guard);
        self::assertNull($context->identity);
        self::assertNull($context->principal);
        self::assertNull($context->tenant);
        self::assertNull($context->device);
        self::assertNull($context->method);
        self::assertNull($context->identityMorphClass);
        self::assertNull($context->identityId);
        self::assertNull($context->principalMorphClass);
        self::assertNull($context->principalId);
        self::assertNull($context->principalCategory);
        self::assertNull($context->tenantMorphClass);
        self::assertNull($context->tenantId);
        self::assertNull($context->deviceId);
    }

    /**
     * A device id a token named is kept when no device row was loaded.
     *
     * @return void
     */
    public function testKeepsANamedDeviceIdWithoutADevice(): void
    {
        $context = new EventContext('api', new ClientContext(null, null), deviceId: 'named-device');

        self::assertNull($context->device);
        self::assertSame('named-device', $context->deviceId);
    }

    /**
     * A loaded device's own identifier wins over a named one.
     *
     * @return void
     */
    public function testALoadedDeviceWinsOverANamedDeviceId(): void
    {
        $context = new EventContext('api', new ClientContext(null, null), device: new PlainDeviceFixture('loaded'), deviceId: 'named');

        self::assertSame('loaded', $context->deviceId);
    }

    /**
     * The snapshot is taken when the context is built: changing the models
     * afterwards changes the live references, not the snapshot.
     *
     * @return void
     */
    public function testSnapshotsDoNotFollowLaterChanges(): void
    {
        $principal = self::typedPrincipal('staff');
        $tenant    = self::tenant(3, 'workspace');

        $principal->forceFill(['id' => 9]);

        $context = new EventContext('api', new ClientContext(null, null), $principal, $principal, $tenant);

        $principal->forceFill(['id' => 10, 'type' => 'service']);
        $tenant->forceFill(['id' => 4]);

        self::assertSame('9', $context->identityId);
        self::assertSame('9', $context->principalId);
        self::assertSame('staff', $context->principalCategory);
        self::assertSame('3', $context->tenantId);
        self::assertSame(10, $context->principal?->getPrincipalIdentifier());
        self::assertSame(4, $context->tenant?->getTenantIdentifier());
    }

    /**
     * `toArray()` is the snapshot as scalars, with no model: the time as an ISO
     * 8601 UTC string to the microsecond whatever the clock's timezone, and the
     * client as its IP address and user agent. It encodes as JSON.
     *
     * @return void
     */
    public function testToArrayIsTheSnapshotAsScalars(): void
    {
        $timezone = date_default_timezone_get();

        date_default_timezone_set('Europe/Paris');

        try {
            CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-04-06 14:00:00.123456'));

            $context = self::fullContext();
        } finally {
            date_default_timezone_set($timezone);
        }

        self::assertInstanceOf(Arrayable::class, $context);
        self::assertSame([
            'occurred_at'           => '2026-04-06T12:00:00.123456Z',
            'guard'                 => 'api',
            'method'                => 'password',
            'ip'                    => '203.0.113.7',
            'user_agent'            => 'agent',
            'identity_morph_class'  => PlainIdentityFixture::class,
            'identity_id'           => '7',
            'principal_morph_class' => $context->principal === null ? null : $context->principal::class,
            'principal_id'          => '5',
            'principal_category'    => 'staff',
            'tenant_morph_class'    => PlainTenantFixture::class,
            'tenant_id'             => '3',
            'device_id'             => 'device-1',
            'credential_id'         => 'key-1',
            'scopes'                => ['read'],
        ], $context->toArray());
        self::assertSame('14', $context->occurredAt->format('H'));
        self::assertJson(json_encode($context->toArray(), JSON_THROW_ON_ERROR));
    }

    /**
     * The snapshot and the other values survive a round trip unchanged, the
     * time to the microsecond; a part that is not an Eloquent model does not
     * cross and comes back `null`.
     *
     * @return void
     */
    public function testSurvivesASerialiseRoundTrip(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-04-06 12:00:00.654321', 'UTC'));

        $client  = new ClientContext('203.0.113.7', 'agent');
        $context = new EventContext(
            'api',
            $client,
            new PlainIdentityFixture(7),
            new PlainPrincipalFixture('p-1'),
            new PlainTenantFixture(3),
            new PlainDeviceFixture('loaded'),
            'password',
            credentialId: 'key-1',
            scopes: ['a', 'b'],
        );

        $copy = unserialize(serialize($context));

        self::assertInstanceOf(EventContext::class, $copy);
        self::assertSame($context->toArray(), $copy->toArray());
        self::assertTrue($context->occurredAt->equalTo($copy->occurredAt));
        self::assertEquals($client, $copy->client);
        self::assertNull($copy->identity);
        self::assertNull($copy->principal);
        self::assertNull($copy->tenant);
        self::assertNull($copy->device);
    }

    /**
     * A context with every part established.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function fullContext(): EventContext
    {
        return new EventContext(
            'api',
            new ClientContext('203.0.113.7', 'agent'),
            new PlainIdentityFixture(7),
            self::typedPrincipal('staff'),
            new PlainTenantFixture(3),
            new PlainDeviceFixture('device-1'),
            'password',
            credentialId: 'key-1',
            scopes: ['read'],
        );
    }

    /**
     * An unsaved tenant model with the given key and, when given, type.
     *
     * @param  int  $id
     * @param  ?string  $type
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private static function tenant(int $id, ?string $type = null): StubTenant
    {
        $tenant = new StubTenant;

        $tenant->forceFill($type === null ? ['id' => $id] : ['id' => $id, 'type' => $type]);

        return $tenant;
    }

    /**
     * An unsaved principal model that reports the given type.
     *
     * @param  string  $type
     * @return \SineMacula\Laravel\Authentication\Contracts\HasType&\Tests\Unit\Stubs\StubPrincipal
     */
    private static function typedPrincipal(string $type): HasType&StubPrincipal
    {
        $principal = new class extends StubPrincipal implements HasType {
            use ProvidesType;
        };

        $principal->forceFill(['id' => 5, 'type' => $type]);

        return $principal;
    }
}
