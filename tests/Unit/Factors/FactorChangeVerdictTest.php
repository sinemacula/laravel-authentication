<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;

/**
 * Unit tests for the factor-change gate's answer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeVerdict::class)]
final class FactorChangeVerdictTest extends TestCase
{
    /**
     * An allowed change carries until when the session stays fresh for it, and
     * no reason.
     *
     * @return void
     */
    public function testAnAllowedChangeCarriesItsDeadline(): void
    {
        $until   = CarbonImmutable::parse('2026-04-06 12:15:00');
        $verdict = FactorChangeVerdict::allowed($until);

        self::assertTrue($verdict->isAllowed());
        self::assertSame($until, $verdict->freshUntil);
        self::assertNull($verdict->reason);
    }

    /**
     * A refused change carries why, and no deadline.
     *
     * @return void
     */
    public function testARefusedChangeCarriesWhy(): void
    {
        $verdict = FactorChangeVerdict::refused(FailureReason::STEP_UP_REQUIRED);

        self::assertFalse($verdict->isAllowed());
        self::assertSame(FailureReason::STEP_UP_REQUIRED, $verdict->reason);
        self::assertNull($verdict->freshUntil);
    }

    /**
     * The constructor is private: a verdict is allowed or refused, never both.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionClass(FactorChangeVerdict::class))->getConstructor()?->isPrivate());
    }
}
