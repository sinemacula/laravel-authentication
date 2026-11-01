<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;

/**
 * Unit tests for the requirement value: the kinds it lists, the strictest of
 * several requirements, and an evaluation of one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Requirement::class)]
#[CoversClass(RequirementEvaluation::class)]
final class RequirementTest extends TestCase
{
    /**
     * The kinds carry the values a further-factor package reports them with.
     *
     * @return void
     */
    public function testTheKindsCarryTheSharedValues(): void
    {
        self::assertSame(
            ['additional_verification', 'multifactor', 'minimum_level', 'phishing_resistance'],
            array_map(static fn (RequirementKind $kind): string => $kind->value, RequirementKind::cases()),
        );
    }

    /**
     * A requirement with no part asks for nothing; one with parts lists their
     * kinds in the order a requirement lists them.
     *
     * @return void
     */
    public function testARequirementListsTheKindsOfItsParts(): void
    {
        self::assertTrue((new Requirement)->isEmpty());
        self::assertSame([], (new Requirement)->kinds());

        $requirement = new Requirement(new RequirementPart, phishingResistance: new RequirementPart(300), minimumLevel: new LevelRequirement(AssuranceLevel::AAL2));

        self::assertFalse($requirement->isEmpty());
        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION, RequirementKind::MINIMUM_LEVEL, RequirementKind::PHISHING_RESISTANCE], $requirement->kinds());
        self::assertSame([RequirementKind::MULTIFACTOR], (new Requirement(multifactor: new RequirementPart))->kinds());
    }

    /**
     * The strictest of several requirements has every part any of them has, the
     * shortest maximum age any gives it (any age only when none gives one), and
     * the highest level asked for; a part only one of them has is that one's
     * own, and none given asks for nothing.
     *
     * @return void
     */
    public function testTheStrictestRequirementCombinesEveryPart(): void
    {
        $only  = new RequirementPart(120);
        $level = new LevelRequirement(AssuranceLevel::AAL2, 120);
        $alone = Requirement::strictest(new Requirement($only, minimumLevel: $level), new Requirement(multifactor: $only));

        self::assertSame($only, $alone->additionalVerification);
        self::assertSame($only, $alone->multifactor);
        self::assertSame($level, $alone->minimumLevel);
        self::assertNull($alone->phishingResistance);
        self::assertTrue(Requirement::strictest()->isEmpty());

        $strictest = Requirement::strictest(
            new Requirement(new RequirementPart(600), minimumLevel: new LevelRequirement(AssuranceLevel::AAL3)),
            new Requirement(new RequirementPart(300), new RequirementPart, new LevelRequirement(AssuranceLevel::AAL2, 900)),
            new Requirement(new RequirementPart, phishingResistance: new RequirementPart(60)),
        );

        self::assertSame(300, $strictest->additionalVerification?->maxAgeSeconds);
        self::assertNotNull($strictest->multifactor);
        self::assertNull($strictest->multifactor->maxAgeSeconds);
        self::assertSame(AssuranceLevel::AAL3, $strictest->minimumLevel?->level);
        self::assertSame(900, $strictest->minimumLevel->maxAgeSeconds);
        self::assertSame(60, $strictest->phishingResistance?->maxAgeSeconds);

        $higherSecond = Requirement::strictest(
            new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL1, 30)),
            new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL2)),
        );

        self::assertSame(AssuranceLevel::AAL2, $higherSecond->minimumLevel?->level);
        self::assertSame(30, $higherSecond->minimumLevel->maxAgeSeconds);
    }

    /**
     * An evaluation is met only when it leaves no kind unmet.
     *
     * @return void
     */
    public function testAnEvaluationIsMetWithNothingUnmet(): void
    {
        self::assertTrue((new RequirementEvaluation([]))->isMet());
        self::assertFalse((new RequirementEvaluation([RequirementKind::MULTIFACTOR]))->isMet());
    }
}
