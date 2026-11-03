<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;

/**
 * The default requirement check: it meets no part of any requirement, so a
 * further factor the identity's or a tenant's policy asks for is never met by
 * a session's proofs until a further-factor package binds a check of its own;
 * only an external provider's evidence that the bound `ExternalEvidencePolicy`
 * accepted and says meets the whole requirement can meet it meanwhile, and its
 * default accepts none. Fail closed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MeetNoRequirement implements RequirementCheck
{
    /**
     * Leave every part of the requirement unmet.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     */
    #[\Override]
    public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation
    {
        return new RequirementEvaluation($requirement->kinds());
    }
}
