<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubTenant;

/**
 * EventContext unit tests: the parts it keeps and the identifiers it snapshots
 * when it is built.
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
    }

    /**
     * The identifiers are snapshotted as strings: the identity's auth
     * identifier, the principal's class and identifier, the tenant's and the
     * device's.
     *
     * @return void
     */
    public function testSnapshotsEveryIdentifierAsAString(): void
    {
        $client  = new ClientContext(null, null);
        $context = new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture(42), self::tenant(3), new PlainDeviceFixture('device-1'));

        self::assertSame('7', $context->identityId);
        self::assertSame(PlainPrincipalFixture::class, $context->principalType);
        self::assertSame('42', $context->principalId);
        self::assertSame('3', $context->tenantId);
        self::assertSame('device-1', $context->deviceId);
    }

    /**
     * An Eloquent principal is recorded by its morph class, as the device row
     * records it, not by its class name.
     *
     * @return void
     */
    public function testRecordsAnEloquentPrincipalByItsMorphClass(): void
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

        $principal->forceFill(['id' => 9]);

        $context = new EventContext('api', new ClientContext(null, null), principal: $principal);

        self::assertSame('member', $context->principalType);
        self::assertSame('9', $context->principalId);
    }

    /**
     * A context with nothing established keeps only the guard and client, and
     * every snapshot is null.
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
        self::assertNull($context->identityId);
        self::assertNull($context->principalType);
        self::assertNull($context->principalId);
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
     * The snapshots are taken when the context is built: changing a model
     * afterwards changes the live reference, not the snapshot.
     *
     * @return void
     */
    public function testSnapshotsDoNotFollowLaterChanges(): void
    {
        $tenant  = self::tenant(3);
        $context = new EventContext('api', new ClientContext(null, null), tenant: $tenant);

        $tenant->forceFill(['id' => 4]);

        self::assertSame('3', $context->tenantId);
        self::assertSame(4, $context->tenant?->getTenantIdentifier());
    }

    /**
     * The context serialises its models as Laravel does, and its snapshots and
     * other values survive a round trip unchanged.
     *
     * @return void
     */
    public function testSurvivesASerialiseRoundTrip(): void
    {
        self::assertContains(SerializesModels::class, class_uses(EventContext::class));

        $client  = new ClientContext('203.0.113.7', 'agent');
        $context = new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture('p-1'), method: 'password', deviceId: 'named');

        $copy = unserialize(serialize($context));

        self::assertInstanceOf(EventContext::class, $copy);
        self::assertSame('api', $copy->guard);
        self::assertSame('203.0.113.7', $copy->client->ip);
        self::assertSame('agent', $copy->client->userAgent);
        self::assertSame('password', $copy->method);
        self::assertSame('7', $copy->identityId);
        self::assertSame(PlainPrincipalFixture::class, $copy->principalType);
        self::assertSame('p-1', $copy->principalId);
        self::assertNull($copy->tenantId);
        self::assertSame('named', $copy->deviceId);
        self::assertSame(7, $copy->identity?->getAuthIdentifier());
    }

    /**
     * An unsaved tenant model with the given key.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private static function tenant(int $id): StubTenant
    {
        $tenant = new StubTenant;

        $tenant->forceFill(['id' => $id]);

        return $tenant;
    }
}
