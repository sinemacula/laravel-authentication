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
use SineMacula\Laravel\Authentication\Events\PrincipalChoiceRequired;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * PrincipalChoiceRequired event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalChoiceRequired::class)]
final class PrincipalChoiceRequiredTest extends TestCase
{
    /**
     * The event keeps its context and expiry.
     *
     * @return void
     */
    public function testKeepsItsContextAndExpiry(): void
    {
        $context   = self::context();
        $expiresAt = CarbonImmutable::parse('2027-01-15 10:05:00');
        $event     = new PrincipalChoiceRequired($context, $expiresAt);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame($expiresAt, $event->expiresAt);
    }

    /**
     * The event serialises its models for queued listeners and survives a round
     * trip, and it does not ask the dispatcher to wait for a transaction: the
     * package dispatches it once the pending choice commits.
     *
     * @return void
     */
    public function testSerialisesItsModelsAndDispatchesWhenTheSenderSays(): void
    {
        $event = new PrincipalChoiceRequired(self::context(), CarbonImmutable::parse('2027-01-15 10:05:00'));

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(PrincipalChoiceRequired::class, $copy);
        self::assertSame('7', $copy->context->identityId);
        self::assertNull($copy->context->principalId);
        self::assertSame('proven-device', $copy->context->deviceId);
        self::assertSame('2027-01-15 10:05:00', $copy->expiresAt->toDateTimeString());
    }

    /**
     * A context for an identity choosing on a device it proved it holds.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext('api', new ClientContext('203.0.113.7', 'agent'), new PlainIdentityFixture(7), device: new PlainDeviceFixture('proven-device'), method: 'password');
    }
}
