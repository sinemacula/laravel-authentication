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
 * for) is accepted at all, and whether accepted evidence meets a requirement on
 * a session's authentication. The default, `InsufficientEvidence`, accepts and
 * meets nothing, so a provider's evidence counts for nothing until the
 * application binds a policy that trusts it. Fail closed.
 *
 * `accepts()` is asked when a sign-in or reauthentication at a provider brings
 * evidence, for no tenant: whether the evidence, from the subject's connection,
 * is credible for the requirement, of any age, to anyone the package may later
 * judge it for (the identity level, or any tenant that trusts the connection).
 * Only accepted evidence is recorded and later judged; `meets()` then scopes
 * it. An application whose tenants each trust their own connections accepts
 * evidence from a connection any of them trusts, and leaves each tenant's
 * requirement to `meets()`.
 *
 * `meets()` is asked for the identity-level requirement (no tenant) and for a
 * tenant's (the subject names it), with accepted evidence only. The evidence
 * must meet the whole requirement: it never combines with a further factor's
 * proofs, which the bound `RequirementCheck` judges. Which factors combine
 * stays the further-factor package's. The package never asks it with a
 * requirement that asks for nothing. An implementation judges any maximum age
 * the requirement's parts give (the shortest) on the evidence's own time
 * against the subject's. One tenant's trust in a connection is not another's:
 * an implementation judging a tenant's requirement refuses evidence from a
 * connection that tenant does not trust, since the tenant a connection belongs
 * to controls what its provider asserts.
 *
 * Both are asked inside `WriteConnection::during()` for the identity, so a
 * model read either makes of its own state (which providers or connections it
 * trusts) sees the primary rather than a replica that may lag behind a change.
 * They may be asked while the package holds a session's row lock (a refresh and
 * a switch judge a tenant's requirement from their issuance guard on, a
 * reauthentication with the new proof recorded under its lock), so an
 * implementation only reads, or takes no lock its caller does not already hold,
 * and never one its caller takes after the session's.
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
     * credible for the requirement, of any age, to anyone it may later be
     * judged for, and so is accepted and recorded.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    public function accepts(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool;

    /**
     * Whether the provider's accepted evidence, with its time, meets the whole
     * requirement for the subject.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool;
}
