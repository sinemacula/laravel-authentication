<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainSessionFixture;
use Tests\Unit\Stubs\PlainTenantFixture;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the snapshots an event context takes from a session row.
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
     * For an event about the session row, the row stands in for an identity,
     * principal or tenant that was not loaded.
     *
     * @return void
     */
    public function testALoadedSessionRowStandsInForAnUnloadedIdentityAndPrincipal(): void
    {
        $session = new StubSession;
        $session->setRawAttributes([
            'id'                   => 'session-1',
            'authenticatable_type' => 'user',
            'authenticatable_id'   => 7,
            'principal_type'       => 'member',
            'principal_id'         => 12,
            'tenant_id'            => 'tenant-5',
        ]);

        $context = new EventContext('api', new ClientContext(null, null), session: $session, fromSession: true);

        self::assertSame('user', $context->identityType);
        self::assertSame('7', $context->identityId);
        self::assertSame('member', $context->principalType);
        self::assertSame('12', $context->principalId);
        self::assertNull($context->tenantType);
        self::assertSame('tenant-5', $context->tenantId);

        $known = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), new PlainPrincipalFixture('p-1'), session: $session, fromSession: true);

        self::assertSame(PlainIdentityFixture::class, $known->identityType);
        self::assertSame('8', $known->identityId);
        self::assertSame(PlainPrincipalFixture::class, $known->principalType);
        self::assertSame('p-1', $known->principalId);

        $principalOnly = new EventContext('api', new ClientContext(null, null), principal: new PlainPrincipalFixture('p-1'), session: $session, fromSession: true);

        self::assertSame('user', $principalOnly->identityType);
        self::assertSame('7', $principalOnly->identityId);
        self::assertSame('p-1', $principalOnly->principalId);

        $identityOnly = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), session: $session, fromSession: true);

        self::assertSame('8', $identityOnly->identityId);
        self::assertSame('member', $identityOnly->principalType);
        self::assertSame('12', $identityOnly->principalId);

        $tenanted = new EventContext('api', new ClientContext(null, null), tenant: new PlainTenantFixture(9), session: $session, fromSession: true);

        self::assertSame(PlainTenantFixture::class, $tenanted->tenantType);
        self::assertSame('9', $tenanted->tenantId);
    }

    /**
     * An event that is not about the session row names only what it holds.
     *
     * @return void
     */
    public function testWithoutFromSessionTheRowStandsInForNothing(): void
    {
        $session = new StubSession;
        $session->setRawAttributes([
            'id'                   => 'session-1',
            'authenticatable_type' => 'user',
            'authenticatable_id'   => 7,
            'principal_type'       => 'member',
            'principal_id'         => 12,
            'tenant_id'            => 'tenant-5',
        ]);

        $bare = new EventContext('api', new ClientContext(null, null), session: $session);

        self::assertNull($bare->identityType);
        self::assertNull($bare->identityId);
        self::assertNull($bare->principalType);
        self::assertNull($bare->principalId);
        self::assertNull($bare->tenantId);
        self::assertSame('session-1', $bare->sessionId);

        $identityOnly = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), session: $session);

        self::assertSame('8', $identityOnly->identityId);
        self::assertNull($identityOnly->principalType);
        self::assertNull($identityOnly->principalId);
    }

    /**
     * A row that records no owner or principal, or a session that is not an
     * Eloquent row, gives no snapshot.
     *
     * @return void
     */
    public function testASessionRecordingNothingGivesNoSnapshot(): void
    {
        $session = new StubSession;
        $session->setRawAttributes(['id' => 'session-1']);

        $bare = new EventContext('api', new ClientContext(null, null), session: $session, fromSession: true);

        self::assertNull($bare->identityType);
        self::assertNull($bare->identityId);
        self::assertNull($bare->principalType);
        self::assertNull($bare->principalId);

        $declared = \Mockery::mock(EloquentSession::class);
        $declared->shouldReceive('getSessionIdentifier')->andReturn('declared');

        foreach ([new PlainSessionFixture('plain'), $declared] as $other) {

            $context = new EventContext('api', new ClientContext(null, null), session: $other, fromSession: true);

            self::assertNull($context->identityType);
            self::assertNull($context->identityId);
            self::assertNull($context->principalType);
            self::assertNull($context->principalId);
        }
    }
}
