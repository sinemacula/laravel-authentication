<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * PrincipalSwitched event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalSwitched::class)]
final class PrincipalSwitchedTest extends TestCase
{
    /**
     * The event keeps its context, the previous principal as the session
     * recorded it, the previous tenant the session recorded, and which of the
     * two changed.
     *
     * @return void
     */
    public function testKeepsItsContextAndThePreviousPrincipal(): void
    {
        $context = self::context();
        $event   = new PrincipalSwitched($context, PlainPrincipalFixture::class, 'p-1', 't-1', true, false);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame(PlainPrincipalFixture::class, $event->previousPrincipalType);
        self::assertSame('p-1', $event->previousPrincipalId);
        self::assertSame('t-1', $event->previousTenantId);
        self::assertTrue($event->principalChanged);
        self::assertFalse($event->tenantChanged);
    }

    /**
     * The event survives a round trip for queued listeners as the values it
     * holds: the recorded morph class and identifiers and the changes are kept.
     * It does not ask the dispatcher to wait for a transaction: the package
     * dispatches it once the switch commits.
     *
     * @return void
     */
    public function testSerializesItsValuesAndDispatchesWhenTheSenderSays(): void
    {
        $event = new PrincipalSwitched(self::context(), 'membership', '9', null, false, true);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(PrincipalSwitched::class, $copy);
        self::assertEquals($event, $copy);
        self::assertSame('7', $copy->context->identityId);
        self::assertSame('p-2', $copy->context->principalId);
        self::assertSame('switched-session', $copy->context->sessionId);
        self::assertSame('membership', $copy->previousPrincipalType);
        self::assertSame('9', $copy->previousPrincipalId);
        self::assertNull($copy->previousTenantId);
        self::assertFalse($copy->principalChanged);
        self::assertTrue($copy->tenantChanged);
    }

    /**
     * A context for an identity that switched to another principal.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        $client = new ClientContext('203.0.113.7', 'agent');

        return new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture('p-2'), null, new PlainSessionFixture('switched-session'), 'password');
    }
}
