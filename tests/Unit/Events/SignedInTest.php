<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * SignedIn event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignedIn::class)]
final class SignedInTest extends TestCase
{
    /**
     * The event keeps its context and whether a refresh renewed the session,
     * and nothing else: every sign-in creates its device, so there is no flag
     * saying so.
     *
     * @return void
     */
    public function testKeepsItsContextAndWhetherARefreshRenewedTheSession(): void
    {
        $context = self::context();
        $event   = new SignedIn($context, false);
        $renewed = new SignedIn($context, true);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertFalse($event->refresh);
        self::assertTrue($renewed->refresh);
        self::assertSame(
            ['context', 'refresh'],
            array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), (new \ReflectionMethod(SignedIn::class, '__construct'))->getParameters()),
        );
    }

    /**
     * The event serialises its models for queued listeners and survives a round
     * trip. It does not ask the dispatcher to wait for a transaction: that
     * would wait for whichever transaction is open last on any connection, so
     * the package dispatches it once the written row's own connection commits.
     *
     * @return void
     */
    public function testSerializesItsModelsAndDispatchesWhenTheSenderSays(): void
    {
        $context = self::context();
        $event   = new SignedIn($context, true);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(SignedIn::class, $copy);
        self::assertSame('api', $copy->context->guard);
        self::assertSame('7', $copy->context->identityId);
        self::assertSame('device-1', $copy->context->deviceId);
        self::assertTrue($copy->refresh);
    }

    /**
     * A context with an identity, principal and device, signed in with a
     * password from a known client.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        $client = new ClientContext('203.0.113.7', 'agent');

        return new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture('p-1'), null, new PlainDeviceFixture('device-1'), 'password');
    }
}
