<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * SessionRevoked event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevoked::class)]
final class SessionRevokedTest extends TestCase
{
    /**
     * The event keeps its context and why the session was revoked.
     *
     * @return void
     */
    public function testKeepsItsContextAndReason(): void
    {
        $context = self::context();
        $event   = new SessionRevoked($context, RevocationReason::ROTATION_REUSE);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame(RevocationReason::ROTATION_REUSE, $event->reason);
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
        $event   = new SessionRevoked($context, RevocationReason::ROTATION_REUSE);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertNotContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(SessionRevoked::class, $copy);
        self::assertSame('api', $copy->context->guard);
        self::assertSame('7', $copy->context->identityId);
        self::assertSame('session-1', $copy->context->sessionId);
        self::assertSame(RevocationReason::ROTATION_REUSE, $copy->reason);
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
