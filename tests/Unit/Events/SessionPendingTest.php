<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * SessionPending event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPending::class)]
final class SessionPendingTest extends TestCase
{
    /**
     * The event keeps its context, what the session waits on in order, and when
     * its pending credential expires.
     *
     * @return void
     */
    public function testKeepsItsContextRequirementsAndExpiry(): void
    {
        $context = self::context();
        $event   = new SessionPending($context, ['mfa', 'principal'], CarbonImmutable::parse('2026-01-01 00:05:00'));

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame(['mfa', 'principal'], $event->requires);
        self::assertEquals(CarbonImmutable::parse('2026-01-01 00:05:00'), $event->expiresAt);
    }

    /**
     * The event holds no model, survives a round trip and leaves its dispatch
     * to the package.
     *
     * @return void
     */
    public function testSerializesItsValuesAndDispatchesWhenTheSenderSays(): void
    {
        $event = new SessionPending(self::context(), ['principal'], CarbonImmutable::parse('2026-01-01 00:05:00'));

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertNotContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(SessionPending::class, $copy);
        self::assertSame('api', $copy->context->guard);
        self::assertSame('7', $copy->context->identityId);
        self::assertNull($copy->context->principalId);
        self::assertSame('session-1', $copy->context->sessionId);
        self::assertSame(['principal'], $copy->requires);
        self::assertEquals(CarbonImmutable::parse('2026-01-01 00:05:00'), $copy->expiresAt);
    }

    /**
     * A context with an identity and a pending session and no principal yet,
     * signed in with a password from a known client.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext('api', new ClientContext('203.0.113.7', 'agent'), new PlainIdentityFixture(7), null, null, new PlainSessionFixture('session-1'), 'password');
    }
}
