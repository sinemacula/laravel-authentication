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
use SineMacula\Laravel\Authentication\Events\IdentifierChanged;
use SineMacula\Laravel\Authentication\Events\IdentifierChangeRequested;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the identifier change events: each keeps its context and the
 * snapshots of the change, and survives queueing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeRequested::class)]
#[CoversClass(IdentifierChanged::class)]
final class IdentifierChangeEventsTest extends TestCase
{
    /**
     * A request keeps its context, the type, the new identifier and when it
     * expires, through a round trip, and leaves the timing of its dispatch to
     * the package.
     *
     * @return void
     */
    public function testARequestKeepsItsSnapshots(): void
    {
        $context   = self::context();
        $expiresAt = CarbonImmutable::parse('2027-03-01 09:30:00');
        $event     = new IdentifierChangeRequested($context, 'email', 'ada@new.example.test', $expiresAt);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses_recursive($event));
        self::assertSame($context, $event->context());

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(IdentifierChangeRequested::class, $copy);
        self::assertSame(['web', '7', 'email', 'ada@new.example.test'], [$copy->context->guard, $copy->context->identityId, $copy->type, $copy->identifier]);
        self::assertTrue($expiresAt->equalTo($copy->expiresAt));
    }

    /**
     * A change keeps its context, the type, both identifiers and when it was
     * made, through a round trip; an identity that had none has no previous
     * identifier.
     *
     * @return void
     */
    public function testAChangeKeepsItsSnapshots(): void
    {
        $context   = self::context();
        $changedAt = CarbonImmutable::parse('2027-03-01 09:00:00');
        $event     = new IdentifierChanged($context, 'email', 'ada@example.test', 'ada@new.example.test', $changedAt);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses_recursive($event));
        self::assertSame($context, $event->context());

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(IdentifierChanged::class, $copy);
        self::assertSame(['web', '7', 'email'], [$copy->context->guard, $copy->context->identityId, $copy->type]);
        self::assertSame(['ada@example.test', 'ada@new.example.test'], [$copy->previous, $copy->identifier]);
        self::assertTrue($changedAt->equalTo($copy->changedAt));
        self::assertNull((new IdentifierChanged($context, 'phone', null, '+447700900456', $changedAt))->previous);
    }

    /**
     * A context with an identity from a known client.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext('web', new ClientContext('203.0.113.7', 'agent'), new PlainIdentityFixture(7));
    }
}
