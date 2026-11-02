<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;

/**
 * Requirement check that finds every requirement met by a first factor alone,
 * as a factor package's would for a requirement its first factor's assurance
 * level already meets: met once the subject's proofs hold a first factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FirstFactorMeetsRequirements implements RequirementCheck
{
    /**
     * Meet the requirement when the subject holds a first factor.
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
        return new RequirementEvaluation($subject->proofs(null, [ProofKind::FIRST_FACTOR], 1) === [] ? $requirement->kinds() : []);
    }
}
