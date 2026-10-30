<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubDevice;

/**
 * EventContext feature tests: for an event about the device row itself, the
 * owner and principal an Eloquent device row records stand in for an identity
 * or principal that was not loaded, read from the columns of the device's
 * relations, the owner's morph class included; any other event names only what
 * it holds.
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
     * For an event about the device row, a loaded row stands in for an identity
     * or principal that was not loaded: the snapshots take the owner and
     * principal it records, and the models stay unknown. A part that was loaded
     * wins over the row.
     *
     * @return void
     */
    public function testALoadedDeviceRowStandsInForAnUnloadedIdentityAndPrincipal(): void
    {
        $device = new StubDevice;
        $device->setRawAttributes(['id' => 'device-1', 'authenticatable_type' => 'user', 'authenticatable_id' => 7, 'principal_type' => 'member', 'principal_id' => 12]);

        $context = new EventContext('api', new ClientContext(null, null), device: $device, fromDevice: true);

        self::assertNull($context->identity);
        self::assertNull($context->principal);
        self::assertSame('user', $context->identityMorphClass);
        self::assertSame('7', $context->identityId);
        self::assertSame('member', $context->principalMorphClass);
        self::assertSame('12', $context->principalId);
        self::assertNull($context->principalCategory);
        self::assertNull($context->tenantMorphClass);
        self::assertNull($context->tenantId);

        $known = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), new PlainPrincipalFixture('p-1'), device: $device, fromDevice: true);

        self::assertSame(PlainIdentityFixture::class, $known->identityMorphClass);
        self::assertSame('8', $known->identityId);
        self::assertSame(PlainPrincipalFixture::class, $known->principalMorphClass);
        self::assertSame('p-1', $known->principalId);

        $principalOnly = new EventContext('api', new ClientContext(null, null), principal: new PlainPrincipalFixture('p-1'), device: $device, fromDevice: true);

        self::assertSame('user', $principalOnly->identityMorphClass);
        self::assertSame('7', $principalOnly->identityId);
        self::assertSame('p-1', $principalOnly->principalId);

        $identityOnly = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), device: $device, fromDevice: true);

        self::assertSame('8', $identityOnly->identityId);
        self::assertSame('member', $identityOnly->principalMorphClass);
        self::assertSame('12', $identityOnly->principalId);
    }

    /**
     * An event that is not about the device row names only what it holds, even
     * when it carries a device that records an owner and a principal: an
     * identity's sign-out everywhere keeping a device, a pending choice with
     * the device the client proved, or a switch refused for its target must not
     * read as acting for the principal the device records.
     *
     * @return void
     */
    public function testWithoutFromDeviceTheRowStandsInForNothing(): void
    {
        $device = new StubDevice;
        $device->setRawAttributes(['id' => 'device-1', 'authenticatable_type' => 'user', 'authenticatable_id' => 7, 'principal_type' => 'member', 'principal_id' => 12]);

        $bare = new EventContext('api', new ClientContext(null, null), device: $device);

        self::assertNull($bare->identityMorphClass);
        self::assertNull($bare->identityId);
        self::assertNull($bare->principalMorphClass);
        self::assertNull($bare->principalId);
        self::assertSame('device-1', $bare->deviceId);

        $identityOnly = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), device: $device);

        self::assertSame('8', $identityOnly->identityId);
        self::assertNull($identityOnly->principalMorphClass);
        self::assertNull($identityOnly->principalId);
    }

    /**
     * Even for an event about the device row, a row that records no owner or
     * principal, or a device that is not an Eloquent row (a device of another
     * kind, or one that only declares the Eloquent contract), gives no
     * snapshot.
     *
     * @return void
     */
    public function testADeviceRecordingNothingGivesNoSnapshot(): void
    {
        $device = new StubDevice;
        $device->setRawAttributes(['id' => 'device-1']);

        $bare = new EventContext('api', new ClientContext(null, null), device: $device, fromDevice: true);

        self::assertNull($bare->identityMorphClass);
        self::assertNull($bare->identityId);
        self::assertNull($bare->principalMorphClass);
        self::assertNull($bare->principalId);

        $declared = \Mockery::mock(EloquentDevice::class);
        $declared->shouldReceive('getDeviceIdentifier')->andReturn('declared');

        foreach ([new PlainDeviceFixture('plain'), $declared] as $other) {

            $context = new EventContext('api', new ClientContext(null, null), device: $other, fromDevice: true);

            self::assertNull($context->identityMorphClass);
            self::assertNull($context->identityId);
            self::assertNull($context->principalMorphClass);
            self::assertNull($context->principalId);
        }
    }
}
