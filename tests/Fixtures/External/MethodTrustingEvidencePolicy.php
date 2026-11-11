<?php

declare(strict_types = 1);

namespace Tests\Fixtures\External;

use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * External evidence policy that trusts each `amr` value for the requirement
 * kinds it was given and keeps the methods it judged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MethodTrustingEvidencePolicy implements ExternalEvidencePolicy
{
    /** @var list<list<string>> The methods of the evidence it was asked to judge, in order. */
    public array $judged = [];

    /**
     * Constructor.
     *
     * @param  array<string, list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>>  $trusted
     */
    public function __construct(

        /** The kinds of requirement each `amr` value meets. */
        private readonly array $trusted,
    ) {}

    /**
     * Accept the evidence when its values cover every kind of the requirement.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    #[\Override]
    public function accepts(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        return $this->covers($evidence, $requirement);
    }

    /**
     * Meet the requirement when the evidence's values cover every kind of it.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return bool
     */
    #[\Override]
    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        $this->judged[] = $evidence->methods;

        return $this->covers($evidence, $requirement);
    }

    /**
     * Whether the evidence's values together cover every kind of the
     * requirement.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return bool
     */
    private function covers(ExternalEvidence $evidence, Requirement $requirement): bool
    {
        $covered = [];

        foreach ($evidence->methods as $method) {
            $covered = [...$covered, ...array_column($this->trusted[$method] ?? [], 'value')];
        }

        return array_diff(array_column($requirement->kinds(), 'value'), $covered) === [];
    }
}
