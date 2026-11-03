<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * SessionReturnedToPending event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionReturnedToPending::class)]
final class SessionReturnedToPendingTest extends TestCase
{
    /**
     * The event keeps its context, what the session waits on, when its pending
     * credential expires, the flow the shortfall was found in, and the previous
     * principal and tenant when the destination changed them.
     *
     * @return void
     */
    public function testKeepsWhatTheReturnChanged(): void
    {
        $context = self::context();
        $event   = new SessionReturnedToPending($context, ['mfa'], CarbonImmutable::parse('2026-01-01 00:05:00'), AuthenticationFlow::REFRESH, 'membership', 'p-0', 'tenant-0');

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context());
        self::assertSame(['mfa'], $event->requires);
        self::assertEquals(CarbonImmutable::parse('2026-01-01 00:05:00'), $event->expiresAt);
        self::assertSame('membership', $event->previousPrincipalType);
        self::assertSame('p-0', $event->previousPrincipalId);
        self::assertSame('tenant-0', $event->previousTenantId);
    }

    /**
     * A return found on refresh changes neither the principal nor the tenant:
     * the previous ones are `null`.
     *
     * @return void
     */
    public function testARefreshNamesNoPreviousContext(): void
    {
        $event = new SessionReturnedToPending(self::context(), ['mfa'], CarbonImmutable::parse('2026-01-01 00:05:00'), AuthenticationFlow::REFRESH);

        self::assertSame(AuthenticationFlow::REFRESH, $event->flow);
        self::assertNull($event->previousPrincipalType);
        self::assertNull($event->previousPrincipalId);
        self::assertNull($event->previousTenantId);
    }

    /**
     * The event holds no model, serialises as it is for queued listeners and
     * survives a round trip, and leaves the dispatch to the package, which
     * waits for the session's own connection to commit.
     *
     * @return void
     */
    public function testSerializesItsValuesAndDispatchesWhenTheSenderSays(): void
    {
        $event = new SessionReturnedToPending(self::context(), ['mfa'], CarbonImmutable::parse('2026-01-01 00:05:00'), AuthenticationFlow::REFRESH, previousTenantId: 'tenant-0');

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertNotContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(SessionReturnedToPending::class, $copy);
        self::assertSame('p-1', $copy->context->principalId);
        self::assertSame('session-1', $copy->context->sessionId);
        self::assertSame(AuthenticationFlow::REFRESH, $copy->flow);
        self::assertSame('tenant-0', $copy->previousTenantId);
    }

    /**
     * A context with an identity, the destination principal and the session.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext(
            'api',
            new ClientContext('203.0.113.7', 'agent'),
            new PlainIdentityFixture(7),
            new PlainPrincipalFixture('p-1'),
            null,
            new PlainSessionFixture('session-1'),
            'password',
        );
    }
}
