<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * SessionActivated event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionActivated::class)]
final class SessionActivatedTest extends TestCase
{
    /**
     * The event keeps the context of the session that activated again.
     *
     * @return void
     */
    public function testKeepsItsContext(): void
    {
        $context = self::context();
        $event   = new SessionActivated($context);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
    }

    /**
     * The event holds no model, survives a round trip and leaves its dispatch
     * to the package.
     *
     * @return void
     */
    public function testSerializesItsValuesAndDispatchesWhenTheSenderSays(): void
    {
        $context = self::context();
        $event   = new SessionActivated($context);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertNotContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(SessionActivated::class, $copy);
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
