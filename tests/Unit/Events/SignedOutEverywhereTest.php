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
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainSessionFixture;

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
     * The event holds no model, survives a round trip and leaves its dispatch
     * to the package.
     *
     * @return void
     */
    public function testSerializesItsValuesAndDispatchesWhenTheSenderSays(): void
    {
        $event = new SignedOutEverywhere(self::context(), RevocationReason::SIGNED_OUT_EVERYWHERE, 0, null);

        self::assertNotInstanceOf(ShouldDispatchAfterCommit::class, $event);
        self::assertNotContains(SerializesModels::class, class_uses_recursive($event));

        $copy = unserialize(serialize($event));

        self::assertInstanceOf(SignedOutEverywhere::class, $copy);
        self::assertSame('7', $copy->context->identityId);
        self::assertSame('kept-session', $copy->context->sessionId);
        self::assertSame(0, $copy->revoked);
        self::assertNull($copy->tokensValidAfter);
    }

    /**
     * A context for an identity's scope that kept one session.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext('api', new ClientContext('203.0.113.7', 'agent'), new PlainIdentityFixture(7), null, null, new PlainSessionFixture('kept-session'));
    }
}
