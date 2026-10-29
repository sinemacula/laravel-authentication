<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * SignedOutEverywhere event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignedOutEverywhere::class)]
final class SignedOutEverywhereTest extends TestCase
{
    /**
     * The event keeps its context, reason, count and cutoff.
     *
     * @return void
     */
    public function testKeepsItsContextReasonCountAndCutoff(): void
    {
        $context = self::context();
        $cutoff  = CarbonImmutable::parse('2027-01-15 10:00:00');
        $event   = new SignedOutEverywhere($context, RevocationReason::PASSWORD_RESET, 3, $cutoff);

        self::assertInstanceOf(AuthenticationEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame(RevocationReason::PASSWORD_RESET, $event->reason);
        self::assertSame(3, $event->revoked);
        self::assertSame($cutoff, $event->tokensValidAfter);
    }

    /**
     * The event serialises its models for queued listeners and survives a round
     * trip, and it does not ask the dispatcher to wait for a transaction: the
     * package dispatches it once the device connection commits.
     *
     * @return void
     */
    public function testSerialisesItsModelsAndDispatchesWhenTheSenderSays(): void
    {
        $event = new SignedOutEverywhere(self::context(), RevocationReason::SIGNED_OUT_EVERYWHERE, 0, null);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(SignedOutEverywhere::class, $copy);
        self::assertSame('7', $copy->context->identityId);
        self::assertSame('kept-device', $copy->context->deviceId);
        self::assertSame(0, $copy->revoked);
        self::assertNull($copy->tokensValidAfter);
    }

    /**
     * A context for an identity's scope that kept one device.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext('api', new ClientContext('203.0.113.7', 'agent'), new PlainIdentityFixture(7), null, null, new PlainDeviceFixture('kept-device'));
    }
}
