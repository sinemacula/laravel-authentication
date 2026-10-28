<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;

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
     * The event keeps its context and the previous principal, as resolved and
     * as the device recorded it.
     *
     * @return void
     */
    public function testKeepsItsContextAndThePreviousPrincipal(): void
    {
        $context  = self::context();
        $previous = new PlainPrincipalFixture('p-1');
        $event    = new PrincipalSwitched($context, $previous, PlainPrincipalFixture::class, 'p-1');

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame($previous, $event->previousPrincipal);
        self::assertSame(PlainPrincipalFixture::class, $event->previousPrincipalType);
        self::assertSame('p-1', $event->previousPrincipalId);
    }

    /**
     * The event serialises its models for queued listeners and survives a round
     * trip, and it does not ask the dispatcher to wait for a transaction: the
     * package dispatches it once the switch commits.
     *
     * @return void
     */
    public function testSerialisesItsModelsAndDispatchesWhenTheSenderSays(): void
    {
        $event = new PrincipalSwitched(self::context(), null, 'membership', '9');

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(PrincipalSwitched::class, $copy);
        self::assertSame('7', $copy->context->identityId);
        self::assertSame('p-2', $copy->context->principalId);
        self::assertSame('switched-device', $copy->context->deviceId);
        self::assertNull($copy->previousPrincipal);
        self::assertSame('membership', $copy->previousPrincipalType);
        self::assertSame('9', $copy->previousPrincipalId);
    }

    /**
     * A context for an identity that switched to another principal.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        $client = new ClientContext('203.0.113.7', 'agent');

        return new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture('p-2'), null, new PlainDeviceFixture('switched-device'), 'password');
    }
}
