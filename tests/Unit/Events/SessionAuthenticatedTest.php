<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\ContextEvent;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * SessionAuthenticated event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionAuthenticated::class)]
#[CoversClass(ContextEvent::class)]
final class SessionAuthenticatedTest extends TestCase
{
    /**
     * The event keeps the context of what the guard bound.
     *
     * @return void
     */
    public function testKeepsItsContext(): void
    {
        $context = self::context();
        $event   = new SessionAuthenticated($context);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
    }

    /**
     * The event serialises its models for queued listeners and survives a round
     * trip; it is dispatched at once, as the guard binds.
     *
     * @return void
     */
    public function testSerializesItsModelsAndDispatchesWhenTheSenderSays(): void
    {
        $context = self::context();
        $event   = new SessionAuthenticated($context);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(SessionAuthenticated::class, $copy);
        self::assertSame('api', $copy->context->guard);
        self::assertSame('7', $copy->context->identityId);
        self::assertSame('session-1', $copy->context->sessionId);
    }

    /**
     * A context with an identity, principal and session, signed in with a
     * password from a known client.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        $client = new ClientContext('203.0.113.7', 'agent');

        return new EventContext('api', $client, new PlainIdentityFixture(7), new PlainPrincipalFixture('p-1'), null, new PlainSessionFixture('session-1'), 'password');
    }
}
