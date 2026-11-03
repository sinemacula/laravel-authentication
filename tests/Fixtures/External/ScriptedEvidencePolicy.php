<?php

declare(strict_types = 1);

namespace Tests\Fixtures\External;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Database\PinningConnectionResolver;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * External evidence policy that trusts a provider's evidence for the kinds of
 * requirement it was given, and accepts or meets a requirement only when it
 * trusts the evidence for every kind the requirement has, as a policy must
 * judge the whole of it. It keeps every question it was asked, in order,
 * whether it was asked to accept the evidence or to judge it, and whether reads
 * were pinned to the write connection when it was.
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
     */
    public function __construct(

        /** The kinds of requirement the evidence meets. */
        private readonly array $trusted = [],
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
     * Meet the requirement when every kind of it is trusted.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    #[\Override]
    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        return $this->isTrusted($evidence, $requirement, $subject, false);
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
