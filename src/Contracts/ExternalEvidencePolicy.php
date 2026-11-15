<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;

/**
 * Decides whether an external identity provider's evidence is accepted, and
 * whether accepted evidence meets a requirement on a session.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ExternalEvidencePolicy
{
    /**
     * Whether the provider's evidence, from the subject's connection, is
     * credible enough to accept and record.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    public function accepts(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool;

    /**
     * Whether the provider's accepted evidence, with its time, meets the whole
     * requirement for the subject; a met answer for an age-bounded requirement
     * reports its `metUntil`, or freshness reads it as not fresh.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     */
    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): RequirementEvaluation;
}
