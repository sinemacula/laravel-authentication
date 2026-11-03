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
 * empty requirement, which is met by definition, nor about a session an
 * external provider established whose accepted evidence the bound
 * `ExternalEvidencePolicy` says meets the whole requirement: that evidence
 * meets it first, and this check is asked only when it does not, never to judge
 * what the evidence left unmet.
 *
 * The subject reads the session's counting proofs through bounded queries on
 * the write connection: ask it for what the requirement needs (by kind, and
 * since the oldest time a part's maximum age allows) rather than the whole
 * history.
 *
 * The package asks it inside `WriteConnection::during()` for the identity, so a
 * model read it makes of its own state (an identity's factors, how a factor is
 * classified), and a query-builder read on the identity's own connection, sees
 * the primary rather than a replica that may lag behind a factor removed or
 * reclassified; any other query-builder read pins itself with
 * `WriteConnection::query()`.
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
