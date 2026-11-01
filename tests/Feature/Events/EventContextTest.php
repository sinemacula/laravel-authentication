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
 * EventContext feature tests: for an event about the session row itself, the
 * owner and principal an Eloquent session row records stand in for an identity
 * or principal that was not loaded, read from the columns of the session's
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
     * For an event about the session row, a loaded row stands in for an
     * identity, principal or tenant that was not loaded: the snapshots take the
     * owner, the principal and the active tenant's identifier it records (with
     * no morph class for the tenant, which the row does not record), and the
     * models stay unknown. A part that was loaded wins over the row.
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

        self::assertNull($context->identity);
        self::assertNull($context->principal);
        self::assertSame('user', $context->identityMorphClass);
        self::assertSame('7', $context->identityId);
        self::assertSame('member', $context->principalMorphClass);
        self::assertSame('12', $context->principalId);
        self::assertNull($context->tenant);
        self::assertNull($context->tenantMorphClass);
        self::assertSame('tenant-5', $context->tenantId);

        $known = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), new PlainPrincipalFixture('p-1'), session: $session, fromSession: true);

        self::assertSame(PlainIdentityFixture::class, $known->identityMorphClass);
        self::assertSame('8', $known->identityId);
        self::assertSame(PlainPrincipalFixture::class, $known->principalMorphClass);
        self::assertSame('p-1', $known->principalId);

        $principalOnly = new EventContext('api', new ClientContext(null, null), principal: new PlainPrincipalFixture('p-1'), session: $session, fromSession: true);

        self::assertSame('user', $principalOnly->identityMorphClass);
        self::assertSame('7', $principalOnly->identityId);
        self::assertSame('p-1', $principalOnly->principalId);

        $identityOnly = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), session: $session, fromSession: true);

        self::assertSame('8', $identityOnly->identityId);
        self::assertSame('member', $identityOnly->principalMorphClass);
        self::assertSame('12', $identityOnly->principalId);

        $tenanted = new EventContext('api', new ClientContext(null, null), tenant: new PlainTenantFixture(9), session: $session, fromSession: true);

        self::assertSame(PlainTenantFixture::class, $tenanted->tenantMorphClass);
        self::assertSame('9', $tenanted->tenantId);
    }

    /**
     * An event that is not about the session row names only what it holds, even
     * when it carries a session that records an owner and a principal: an
     * identity's sign-out everywhere keeping a session, a pending choice with
     * the session the client proved, or a switch refused for its target must
     * not read as acting for the principal the session records.
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

        self::assertNull($bare->identityMorphClass);
        self::assertNull($bare->identityId);
        self::assertNull($bare->principalMorphClass);
        self::assertNull($bare->principalId);
        self::assertNull($bare->tenantId);
        self::assertSame('session-1', $bare->sessionId);

        $identityOnly = new EventContext('api', new ClientContext(null, null), new PlainIdentityFixture(8), session: $session);

        self::assertSame('8', $identityOnly->identityId);
        self::assertNull($identityOnly->principalMorphClass);
        self::assertNull($identityOnly->principalId);
    }

    /**
     * Even for an event about the session row, a row that records no owner or
     * principal, or a session that is not an Eloquent row (a session of another
     * kind, or one that only declares the Eloquent contract), gives no
     * snapshot.
     *
     * @return void
     */
    public function testASessionRecordingNothingGivesNoSnapshot(): void
    {
        $session = new StubSession;
        $session->setRawAttributes(['id' => 'session-1']);

        $bare = new EventContext('api', new ClientContext(null, null), session: $session, fromSession: true);

        self::assertNull($bare->identityMorphClass);
        self::assertNull($bare->identityId);
        self::assertNull($bare->principalMorphClass);
        self::assertNull($bare->principalId);

        $declared = \Mockery::mock(EloquentSession::class);
        $declared->shouldReceive('getSessionIdentifier')->andReturn('declared');

        foreach ([new PlainSessionFixture('plain'), $declared] as $other) {

            $context = new EventContext('api', new ClientContext(null, null), session: $other, fromSession: true);

            self::assertNull($context->identityMorphClass);
            self::assertNull($context->identityId);
            self::assertNull($context->principalMorphClass);
            self::assertNull($context->principalId);
        }
    }
}
