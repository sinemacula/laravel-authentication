<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * ExternalResultUnlinked event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalResultUnlinked::class)]
final class ExternalResultUnlinkedTest extends TestCase
{
    /**
     * The event keeps its context, the connection and the issuer, and has no
     * property for the subject or anything else the provider asserted.
     *
     * @return void
     */
    public function testKeepsItsContextConnectionAndIssuerOnly(): void
    {
        $context = self::context();
        $event   = new ExternalResultUnlinked($context, 'connection-7', 'https://idp.example.test');

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame(['connection-7', 'https://idp.example.test'], [$event->connectionId, $event->issuer]);
        self::assertSame(['context', 'connectionId', 'issuer'], array_keys(get_object_vars($event)));
    }

    /**
     * The event serialises for queued listeners and survives a round trip; it
     * is dispatched when the package dispatches it, not after a commit.
     *
     * @return void
     */
    public function testSerializesAndDispatchesWhenTheSenderSays(): void
    {
        $event = new ExternalResultUnlinked(self::context(), 'connection-7', 'https://idp.example.test');

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertNotContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(ExternalResultUnlinked::class, $copy);
        self::assertSame('api', $copy->context->guard);
        self::assertNull($copy->context->identityId);
        self::assertSame(['connection-7', 'https://idp.example.test'], [$copy->connectionId, $copy->issuer]);
    }

    /**
     * A context with no identity, from a known client.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext('api', new ClientContext('203.0.113.7', 'agent'));
    }
}
