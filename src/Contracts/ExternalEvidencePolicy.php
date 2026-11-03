<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * External evidence policy contract.
 *
 * Says whether the evidence an external identity provider asserted (its `amr`
 * values, its `acr` value or SAML authentication context, with the time it is
 * for) meets a requirement on a session's authentication. The package asks it
 * for the identity-level requirement and for a tenant's alike, and it decides
 * whether a provider's evidence is accepted at all. The default,
 * `InsufficientEvidence`, meets nothing, and a session with no evidence meets
 * nothing through it, so a provider's evidence counts for nothing until the
 * application binds a policy that trusts it. Fail closed.
 *
 * The evidence must meet the whole requirement: it never combines with a
 * further factor's proofs, which the bound `RequirementCheck` judges. Which
 * factors combine stays the further-factor package's. The package never asks it
 * with a requirement that asks for nothing. An implementation judges any
 * maximum age the requirement's parts give (the shortest) on the evidence's own
 * time against the subject's.
 *
 * The subject names the tenant whose requirement is judged (none for the
 * identity-level requirement and for the evidence's acceptance). One tenant's
 * trust in a connection is not another's: an implementation judging a tenant's
 * requirement refuses evidence from a connection that tenant does not trust,
 * since the tenant a connection belongs to controls what its provider asserts.
 *
 * It is asked inside `WriteConnection::during()` for the identity, so a model
 * read it makes of its own state (which providers or connections it trusts)
 * sees the primary rather than a replica that may lag behind a change.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ExternalEvidencePolicy
{
    /**
     * Whether the provider's evidence, with its time, meets the whole
     * requirement for the subject.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool;
}
