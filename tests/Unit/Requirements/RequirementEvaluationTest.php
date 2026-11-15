<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;

/**
 * Unit tests for a check's answer about a requirement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementEvaluation::class)]
final class RequirementEvaluationTest extends TestCase
{
    /**
     * An evaluation is met only when it leaves no kind unmet, whether or not it
     * says until when.
     *
     * @return void
     */
    public function testAnEvaluationIsMetWithNothingUnmet(): void
    {
        $until = CarbonImmutable::parse('2026-04-06 12:10:00');
        $met   = new RequirementEvaluation([], $until);

        self::assertTrue((new RequirementEvaluation([]))->isMet());
        self::assertNull((new RequirementEvaluation([]))->metUntil);
        self::assertTrue($met->isMet());
        self::assertSame($until, $met->metUntil);
        self::assertFalse((new RequirementEvaluation([RequirementKind::MULTIFACTOR]))->isMet());
    }

    /**
     * An evaluation with unmet parts and a time it is met until is refused.
     *
     * @return void
     */
    public function testAnUnmetEvaluationWithATimeItIsMetUntilIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A requirement evaluation with unmet parts has no time it is met until.');

        new RequirementEvaluation([RequirementKind::MINIMUM_LEVEL], CarbonImmutable::parse('2026-04-06 12:10:00'));
    }
}
