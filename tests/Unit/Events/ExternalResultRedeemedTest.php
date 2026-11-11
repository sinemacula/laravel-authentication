<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * ExternalResultRedeemed event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalResultRedeemed::class)]
final class ExternalResultRedeemedTest extends TestCase
{
    /**
     * The event keeps its context, with the connection and the request
     * reference, and what the result was redeemed for.
     *
     * @return void
     */
    public function testKeepsItsContextAndFlow(): void
    {
        $context = self::context();
        $event   = new ExternalResultRedeemed($context, AuthenticationFlow::REAUTHENTICATION);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame(AuthenticationFlow::REAUTHENTICATION, $event->flow);
        self::assertSame(['connection-7', 'request-3'], [$event->context->connectionId, $event->context->requestReference]);
    }

    /**
     * The event survives a round trip and leaves its dispatch to the package.
     *
     * @return void
     */
    public function testSerializesItsValuesAndDispatchesWhenTheSenderSays(): void
    {
        $event = new ExternalResultRedeemed(self::context(), AuthenticationFlow::SIGN_IN);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(ExternalResultRedeemed::class, $copy);
        self::assertEquals($event, $copy);
    }

    /**
     * The context of a session a result was redeemed into.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        $client  = new ClientContext('203.0.113.7', 'agent');
        $session = new PlainSessionFixture('session-1');

        return new EventContext(
            'api',
            $client,
            new PlainIdentityFixture(7),
            session: $session,
            method: 'external_provider',
            connectionId: 'connection-7',
            requestReference: 'request-3',
        );
    }
}
