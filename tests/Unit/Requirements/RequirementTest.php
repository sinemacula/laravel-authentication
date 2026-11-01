<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;

/**
 * Unit tests for the requirement value: its parts and their maximum ages, the
 * kinds it lists, and the strictest of several requirements.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Requirement::class)]
#[CoversClass(RequirementPart::class)]
#[CoversClass(LevelRequirement::class)]
#[CoversClass(RequirementEvaluation::class)]
#[CoversClass(AssuranceLevel::class)]
final class RequirementTest extends TestCase
{
    /**
     * The kinds and the levels carry the values a further-factor package
     * reports them with.
     *
     * @return void
     */
    public function testTheEnumsCarryTheSharedValues(): void
    {
        self::assertSame(
            ['additional_verification', 'multifactor', 'minimum_level', 'phishing_resistance'],
            array_map(static fn (RequirementKind $kind): string => $kind->value, RequirementKind::cases()),
        );
        self::assertSame(['aal1', 'aal2', 'aal3'], array_map(static fn (AssuranceLevel $level): string => $level->value, AssuranceLevel::cases()));
    }

    /**
     * A level is at least itself and every lower level, and never a higher one.
     *
     * @return void
     */
    public function testALevelIsAtLeastTheLevelsBelowIt(): void
    {
        self::assertTrue(AssuranceLevel::AAL2->isAtLeast(AssuranceLevel::AAL1));
        self::assertTrue(AssuranceLevel::AAL2->isAtLeast(AssuranceLevel::AAL2));
        self::assertFalse(AssuranceLevel::AAL2->isAtLeast(AssuranceLevel::AAL3));
        self::assertTrue(AssuranceLevel::AAL3->isAtLeast(AssuranceLevel::AAL1));
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
     * the highest level asked for; none given asks for nothing.
     *
     * @return void
     */
    public function testTheStrictestRequirementCombinesEveryPart(): void
    {
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
     * Rows of `[maximum age]` a part refuses.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideRefusedAges(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
        yield 'over a year' => [RequirementPart::MAX_AGE_SECONDS + 1];
    }

    /**
     * A maximum age outside one second to a year is refused, by a part and by a
     * level alike.
     *
     * @param  int  $age
     * @return void
     */
    #[DataProvider('provideRefusedAges')]
    public function testAMaximumAgeOutsideItsRangeIsRefused(int $age): void
    {
        foreach ([static fn (): object => new RequirementPart($age), static fn (): object => new LevelRequirement(AssuranceLevel::AAL1, $age)] as $make) {
            try {
                $make();

                self::fail('Expected the maximum age to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A requirement\'s maximum age must be between 1 and 31536000 seconds.', $exception->getMessage());
            }
        }

        self::assertSame(RequirementPart::MAX_AGE_SECONDS, (new RequirementPart(RequirementPart::MAX_AGE_SECONDS))->maxAgeSeconds);
        self::assertSame(1, (new LevelRequirement(AssuranceLevel::AAL1, 1))->maxAgeSeconds);
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
