<?php

declare(strict_types = 1);

namespace Tests\Unit\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\RateLimiting\LimitedOutcome;

/**
 * Unit tests for the outcome of a flow that may be rate limited: it carries the
 * outcome and the wait it was given, and says which outcome it is only for that
 * very case.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LimitedOutcome::class)]
final class LimitedOutcomeTest extends TestCase
{
    /**
     * An outcome carries no wait unless given one, and is only itself.
     *
     * @return void
     */
    public function testAnOutcomeIsOnlyItself(): void
    {
        $verified = new LimitedOutcome(VerificationOutcome::VERIFIED);

        self::assertSame([VerificationOutcome::VERIFIED, null], [$verified->outcome, $verified->retryAfter]);
        self::assertTrue($verified->is(VerificationOutcome::VERIFIED));
        self::assertFalse($verified->is(VerificationOutcome::ALREADY_VERIFIED));
    }

    /**
     * A limited outcome carries its wait.
     *
     * @return void
     */
    public function testALimitedOutcomeCarriesItsWait(): void
    {
        $limited = new LimitedOutcome(IdentifierChangeOutcome::RATE_LIMITED, 42);

        self::assertSame([IdentifierChangeOutcome::RATE_LIMITED, 42], [$limited->outcome, $limited->retryAfter]);
        self::assertTrue($limited->is(IdentifierChangeOutcome::RATE_LIMITED));
        self::assertFalse($limited->is(IdentifierChangeOutcome::CHANGED));
    }
}
