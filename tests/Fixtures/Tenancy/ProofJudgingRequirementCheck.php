<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;

/**
 * Requirement check that finds a requirement met once the subject's proofs hold
 * an accepted further factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ProofJudgingRequirementCheck implements RequirementCheck
{
    /** @var list<\SineMacula\Laravel\Authentication\Requirements\RequirementSubject> The subjects it judged, in order. */
    public array $judged = [];

    /**
     * Meet the requirement when the subject holds a further factor.
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
        $this->judged[] = $subject;

        $factors = $subject->proofs(null, [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], 1);

        return new RequirementEvaluation($factors === [] ? $requirement->kinds() : []);
    }
}
