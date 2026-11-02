<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\FactorCodeCheck;

/**
 * Unit tests for how a check of a factor code ended: what it carries, and that
 * only a verified one says so.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorCodeCheck::class)]
#[CoversClass(FactorCodeOutcome::class)]
final class FactorCodeCheckTest extends TestCase
{
    /**
     * The check keeps what it was given; only `verified` is verified.
     *
     * @return void
     */
    public function testOnlyAVerifiedCheckSaysSo(): void
    {
        $at    = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $until = $at->addMinutes(15);
        $check = new FactorCodeCheck(FactorCodeOutcome::LOCKED, 'challenge-1', null, $until, FactorCodeRefusal::NOT_ACCEPTED, 30);

        self::assertSame(
            [FactorCodeOutcome::LOCKED, 'challenge-1', null, $until, FactorCodeRefusal::NOT_ACCEPTED, 30],
            [$check->outcome, $check->challengeId, $check->verifiedAt, $check->lockedUntil, $check->reason, $check->retryAfter],
        );
        self::assertTrue((new FactorCodeCheck(FactorCodeOutcome::VERIFIED, 'challenge-1', $at))->isVerified());

        foreach (FactorCodeOutcome::cases() as $outcome) {
            self::assertSame($outcome === FactorCodeOutcome::VERIFIED, (new FactorCodeCheck($outcome, 'challenge-1'))->isVerified());
        }
    }

    /**
     * The outcomes and their values.
     *
     * @return void
     */
    public function testTheOutcomes(): void
    {
        self::assertSame(
            ['verified', 'invalid', 'expired', 'exhausted', 'locked', 'refused', 'rate_limited'],
            array_column(FactorCodeOutcome::cases(), 'value'),
        );
    }
}
