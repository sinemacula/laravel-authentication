<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;

/**
 * Requirement check contract.
 *
 * Judges whether a session's proofs meet a requirement on its authentication (a
 * further factor, multifactor, a minimum assurance level, phishing resistance,
 * each with an optional maximum age). The package's default,
 * `MeetNoRequirement`, meets none, so a requirement a further-factor package
 * has not been bound to judge fails closed. The package never asks it with an
 * empty requirement, which is met by definition.
 *
 * The subject reads the session's counting proofs through bounded queries on
 * the write connection: ask it for what the requirement needs (by kind, and
 * since the oldest time a part's maximum age allows) rather than the whole
 * history.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RequirementCheck
{
    /**
     * Judge the subject's proofs against the requirement.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     */
    public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation;
}
