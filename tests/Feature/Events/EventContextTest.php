<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubDevice;

/**
 * EventContext feature tests: the owner and principal an Eloquent device row
 * records stand in for an identity or principal that was not loaded, read from
 * the columns of the device's relations.
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
     * A loaded device row stands in for an identity or principal that was not
     * loaded: the snapshots take the owner and principal it records, and the
     * models stay unknown. A part that was loaded wins over the row.
     *
     * @return void
     */
    public function testALoadedDeviceRowStandsInForAnUnloadedIdentityAndPrincipal(): void
    {
        $device = new StubDevice;
        $device->setRawAttributes(['id' => 'device-1', 'authenticatable_type' => 'user', 'authenticatable_id' => 7, 'principal_type' => 'member', 'principal_id' => 12]);

        $context = new EventContext('api', new ClientContext(null, null), device: $device);

        self::assertNull($context->identity);
        self::assertNull($context->principal);
        self::assertSame('7', $context->identityId);
        self::assertSame('member', $context->principalType);
        self::assertSame('12', $context->principalId);
        self::assertNull($context->tenantId);

        $known = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), new PlainPrincipalFixture('p-1'), device: $device);

        self::assertSame('8', $known->identityId);
        self::assertSame(PlainPrincipalFixture::class, $known->principalType);
        self::assertSame('p-1', $known->principalId);

        $principalOnly = new EventContext('api', new ClientContext(null, null), principal: new PlainPrincipalFixture('p-1'), device: $device);

        self::assertSame('7', $principalOnly->identityId);
        self::assertSame('p-1', $principalOnly->principalId);
    }

    /**
     * A device row that records no owner or principal, or a device that is not
     * an Eloquent row, gives no snapshot.
     *
     * @return void
     */
    public function testADeviceRecordingNothingGivesNoSnapshot(): void
    {
        $device = new StubDevice;
        $device->setRawAttributes(['id' => 'device-1']);

        $bare = new EventContext('api', new ClientContext(null, null), device: $device);

        self::assertNull($bare->identityId);
        self::assertNull($bare->principalType);
        self::assertNull($bare->principalId);

        $plain = new EventContext('api', new ClientContext(null, null), device: new PlainDeviceFixture('plain'));

        self::assertNull($plain->identityId);
        self::assertNull($plain->principalType);
        self::assertNull($plain->principalId);
    }
}
