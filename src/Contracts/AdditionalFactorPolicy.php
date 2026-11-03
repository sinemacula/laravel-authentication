<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * Additional-factor policy contract.
 *
 * Asked about the identity, after its first factor has verified it and the
 * application has admitted it, and before any principal is chosen, what its
 * session's authentication must include beyond that first factor: an additional
 * verification, multifactor authentication, a minimum assurance level, phishing
 * resistance, each with an optional maximum age. The answer is this package's
 * own `Requirement`; one that asks for nothing lets the session activate. The
 * package's default asks for nothing; a factor package or the application binds
 * its own policy in the container. A tenant that asks more of a session says so
 * through the tenant authentication policy instead.
 *
 * Whether a session meets a non-empty answer is never this policy's to judge:
 * for a session an external provider established, the bound
 * `ExternalEvidencePolicy` is asked first whether the provider's accepted
 * evidence meets the whole of it, and otherwise the bound `RequirementCheck`
 * judges the session's proofs. Both defaults meet nothing, so a requirement
 * neither was bound to meet keeps the session pending (fail closed). At sign-in
 * they judge the first factor (and its accepted evidence) alone, so a
 * requirement it meets activates the session at once. Otherwise the session is
 * pending, with a short-lived pending credential that cannot authenticate a
 * request, holding no token, until the factor's verifier hands it the proofs
 * that meet the requirement (`satisfy()`). The policy is asked again each time
 * the pending session is acted on, when a refresh or a switch returns the
 * session to pending under its tenant's authentication policy (never when that
 * policy is met), and when the removal of a factor judges the current session
 * again.
 *
 * It is asked inside `WriteConnection::during()` for the identity, so a model
 * read it makes of the identity's own state sees the primary.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AdditionalFactorPolicy
{
    /**
     * What the session's authentication must include beyond its first factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    public function requirementFor(AdditionalFactorContext $context): Requirement;
}
