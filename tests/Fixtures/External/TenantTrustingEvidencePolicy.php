<?php

declare(strict_types = 1);

namespace Tests\Fixtures\External;

use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * External evidence policy that trusts a connection's evidence for a tenant's
 * requirement only when that tenant trusts the connection, as a policy must:
 * one tenant's connection never meets another tenant's requirement. It accepts
 * evidence from a connection any tenant trusts, and meets the identity-level
 * requirement only with evidence from a connection trusted for it (under the
 * empty identifier). It keeps every subject it was asked about, in order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantTrustingEvidencePolicy implements ExternalEvidencePolicy
{
    /** @var list<\SineMacula\Laravel\Authentication\External\EvidenceSubject> The subjects it was asked about, in order. */
    public array $subjects = [];

    /**
     * Constructor.
     *
     * @param  array<string, list<string>>  $trusted
     */
    public function __construct(

        /** The connections each tenant trusts, by the tenant's identifier; the identity level's under `''`. */
        private readonly array $trusted,
    ) {}

    /**
     * Accept the evidence when any tenant, or the identity level, trusts the
     * connection that asserted it.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    #[\Override]
    public function accepts(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        $this->subjects[] = $subject;

        return in_array($subject->connectionId, array_merge(...array_values($this->trusted)), true);
    }

    /**
     * Meet the requirement when the tenant it is judged for, or the identity
     * level when it is judged for none, trusts the connection that asserted the
     * evidence.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    #[\Override]
    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        $this->subjects[] = $subject;

        $tenant = IdentifierCoercion::stringify($subject->tenant?->getTenantIdentifier()) ?? '';

        return in_array($subject->connectionId, $this->trusted[$tenant] ?? [], true);
    }
}
