<?php

declare(strict_types = 1);

namespace Tests\Unit\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * Unit tests for an attempt reservation and the subject it was made for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptReservation::class)]
#[CoversClass(AttemptSubject::class)]
final class AttemptReservationTest extends TestCase
{
    /**
     * A reservation without a wait is granted and keeps the windows it took.
     *
     * @return void
     */
    public function testAReservationWithoutAWaitIsGranted(): void
    {
        $subject     = new AttemptSubject('api', AttemptFlow::SIGN_IN, 'ada@example.test', 'email', '203.0.113.7');
        $reservation = new AttemptReservation($subject, null, ['k' => '2026-04-06 12:05:00']);

        self::assertTrue($reservation->granted());
        self::assertSame($subject, $reservation->subject);
        self::assertSame(['k' => '2026-04-06 12:05:00'], $reservation->windows);
        self::assertSame('api', $subject->guard);
        self::assertSame(AttemptFlow::SIGN_IN, $subject->flow);
        self::assertSame('ada@example.test', $subject->identifier);
        self::assertSame('email', $subject->identifierType);
        self::assertSame('203.0.113.7', $subject->ip);
    }

    /**
     * A reservation that carries a wait is refused and took nothing.
     *
     * @return void
     */
    public function testAReservationWithAWaitIsRefused(): void
    {
        $reservation = new AttemptReservation(new AttemptSubject('api', AttemptFlow::REFRESH, null, null, null), 30);

        self::assertFalse($reservation->granted());
        self::assertSame(30, $reservation->retryAfter);
        self::assertSame([], $reservation->windows);
    }

    /**
     * The flows' values name their blocks in the `rate_limits` configuration.
     *
     * @return void
     */
    public function testFlowsNameTheirConfigurationBlocks(): void
    {
        $flows = array_map(static fn (AttemptFlow $flow): string => $flow->value, AttemptFlow::cases());

        self::assertSame(['sign_in', 'refresh', 'code_request', 'passkey_options', 'client_credentials'], $flows);
    }
}
