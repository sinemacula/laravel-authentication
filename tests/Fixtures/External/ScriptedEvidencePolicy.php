<?php

declare(strict_types = 1);

namespace Tests\Fixtures\External;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Database\PinningConnectionResolver;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;

/**
 * External evidence policy that trusts a provider's evidence for the
 * requirement kinds it was given and keeps every question asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedEvidencePolicy implements ExternalEvidencePolicy
{
    /** @var list<array{evidence: \SineMacula\Laravel\Authentication\External\ExternalEvidence, requirement: \SineMacula\Laravel\Authentication\Requirements\Requirement, subject: \SineMacula\Laravel\Authentication\External\EvidenceSubject, pinned: bool, accepting: bool}> The questions it was asked, in order. */
    public array $asked = [];

    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>  $trusted
     * @param  ?int  $metForSeconds
     */
    public function __construct(

        /** The kinds of requirement the evidence meets. */
        private readonly array $trusted = [],

        /** How long after its time the evidence is reported met until, `null` for no such time. */
        private readonly ?int $metForSeconds = null,
    ) {}

    /**
     * Accept the evidence when every kind of the requirement is trusted.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    #[\Override]
    public function accepts(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        return $this->isTrusted($evidence, $requirement, $subject, true);
    }

    /**
     * Meet the requirement when every kind of it is trusted, until the time
     * scripted.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     */
    #[\Override]
    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): RequirementEvaluation
    {
        if (!$this->isTrusted($evidence, $requirement, $subject, false)) {
            return new RequirementEvaluation($requirement->kinds());
        }

        return new RequirementEvaluation([], $this->metForSeconds === null ? null : $evidence->authenticatedAt->addSeconds($this->metForSeconds));
    }

    /**
     * Keep the question and answer it: whether every kind of the requirement is
     * trusted.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @param  bool  $accepting
     * @return bool
     */
    private function isTrusted(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject, bool $accepting): bool
    {
        $this->asked[] = [
            'evidence'    => $evidence,
            'requirement' => $requirement,
            'subject'     => $subject,
            'pinned'      => Model::getConnectionResolver() instanceof PinningConnectionResolver,
            'accepting'   => $accepting,
        ];

        return array_diff(array_column($requirement->kinds(), 'value'), array_column($this->trusted, 'value')) === [];
    }
}
