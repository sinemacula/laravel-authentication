<?php

declare(strict_types = 1);

namespace Tests\Unit\External;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the default external evidence policy, which finds every
 * provider's evidence insufficient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InsufficientEvidence::class)]
final class InsufficientEvidenceTest extends TestCase
{
    /**
     * The default meets no requirement with any evidence, even the strongest a
     * provider can assert for the weakest requirement, so a provider's evidence
     * counts for nothing until a policy that trusts it is bound.
     *
     * @return void
     */
    public function testNoEvidenceMeetsAnyRequirement(): void
    {
        $now      = CarbonImmutable::parse('2026-04-06 12:00:00');
        $evidence = new ExternalEvidence(['hwk', 'pin', 'mfa'], 'phrh', $now);
        $subject  = new EvidenceSubject(new PlainIdentityFixture(7), 'api', 'conn-a', $now);
        $policy   = new InsufficientEvidence;

        self::assertFalse($policy->meets($evidence, new Requirement(additionalVerification: new RequirementPart), $subject));
        self::assertFalse($policy->meets($evidence, new Requirement(multifactor: new RequirementPart), $subject));
    }

    /**
     * The default accepts no evidence, even the strongest a provider can
     * assert, so none is ever recorded until a policy that trusts it is bound.
     *
     * @return void
     */
    public function testNoEvidenceIsAccepted(): void
    {
        $now      = CarbonImmutable::parse('2026-04-06 12:00:00');
        $evidence = new ExternalEvidence(['hwk', 'pin', 'mfa'], 'phrh', $now);
        $subject  = new EvidenceSubject(new PlainIdentityFixture(7), 'api', 'conn-a', $now);
        $policy   = new InsufficientEvidence;

        self::assertFalse($policy->accepts($evidence, new Requirement(multifactor: new RequirementPart), $subject));
        self::assertFalse($policy->accepts($evidence, new Requirement(phishingResistance: new RequirementPart), $subject));
    }
}
