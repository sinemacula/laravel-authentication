<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * AuthenticationFailed event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationFailed::class)]
final class AuthenticationFailedTest extends TestCase
{
    /**
     * The event keeps its context, the flow that failed, the reason, the
     * identifier the input named and the wait.
     *
     * @return void
     */
    public function testKeepsItsContextFlowReasonIdentifierAndWait(): void
    {
        $context = self::context();
        $event   = new AuthenticationFailed($context, AuthenticationFlow::SIGN_IN, FailureReason::ACCOUNT_RATE_LIMITED, 'ada@example.test', 30);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame(AuthenticationFlow::SIGN_IN, $event->flow);
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $event->reason);
        self::assertSame('ada@example.test', $event->identifier);
        self::assertSame(30, $event->retryAfter);
    }

    /**
     * The event serialises its models for queued listeners and survives a round
     * trip; it is dispatched at once, by the flow that failed.
     *
     * @return void
     */
    public function testSerialisesItsModelsAndDispatchesWhenTheSenderSays(): void
    {
        $context = self::context();
        $event   = new AuthenticationFailed($context, AuthenticationFlow::SIGN_IN, FailureReason::ACCOUNT_RATE_LIMITED, 'ada@example.test', 30);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(AuthenticationFailed::class, $copy);
        self::assertSame('api', $copy->context->guard);
        self::assertSame('7', $copy->context->identityId);
        self::assertSame('device-1', $copy->context->deviceId);
        self::assertSame(AuthenticationFlow::SIGN_IN, $copy->flow);
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $copy->reason);
        self::assertSame('ada@example.test', $copy->identifier);
        self::assertSame(30, $copy->retryAfter);
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
