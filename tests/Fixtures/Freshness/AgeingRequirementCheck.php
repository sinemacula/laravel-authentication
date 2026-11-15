<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Freshness;

use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;

/**
 * Requirement check that meets every part with the subject's newest further
 * factor made within the shortest maximum age, until that factor is too old.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AgeingRequirementCheck implements RequirementCheck
{
    /**
     * Meet the requirement with the newest further factor within its age.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation
    {
        $maxAge = null;

        foreach ([$requirement->additionalVerification, $requirement->multifactor, $requirement->minimumLevel, $requirement->phishingResistance] as $part) {
            $maxAge = RequirementPart::shorter($maxAge, $part?->maxAgeSeconds);
        }

        $proof = $subject->proofs($maxAge === null ? null : $subject->now->subSeconds($maxAge), [ProofKind::ADDITIONAL_FACTOR], 1)[0] ?? null;

        return $proof === null
            ? new RequirementEvaluation($requirement->kinds())
            : new RequirementEvaluation([], $maxAge === null ? null : $proof->authenticatedAt->addSeconds($maxAge));
    }
}
