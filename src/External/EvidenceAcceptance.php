<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;

/**
 * Decides whether an external provider's evidence is accepted at all, and so
 * whether it is recorded and counts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EvidenceAcceptance
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The evaluation of the evidence once accepted, or `null` when it is
     * insufficient.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Evaluation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function evaluate(ExternalEvidence $evidence, EvidenceSubject $subject): ?Evaluation
    {
        $evidence = self::asOf($evidence, $subject);
        $policy   = Container::getInstance()->make(ExternalEvidencePolicy::class);

        $accepts = static fn (Requirement $requirement): bool => WriteConnection::during(
            $subject->identity,
            static fn (): bool => $policy->accepts($evidence, $requirement, $subject),
        );

        $answers = [
            [new Requirement(multifactor: new RequirementPart), new Evaluation(true, true, true)],
            [new Requirement(additionalVerification: new RequirementPart), new Evaluation(true, false, true)],
            [new Requirement(phishingResistance: new RequirementPart), new Evaluation(true, false, false)],
            [new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL1)), new Evaluation(true, false, false)],
        ];

        foreach ($answers as [$requirement, $evaluation]) {
            if ($accepts($requirement)) {
                return $evaluation;
            }
        }

        return null;
    }

    /**
     * The evidence as it is judged at the subject's time, dated no later than
     * that time.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @return \SineMacula\Laravel\Authentication\External\ExternalEvidence
     *
     * @throws \InvalidArgumentException
     */
    public static function asOf(ExternalEvidence $evidence, EvidenceSubject $subject): ExternalEvidence
    {
        return $evidence->authenticatedAt->greaterThan($subject->now)
            ? new ExternalEvidence($evidence->methods, $evidence->context, $subject->now)
            : $evidence;
    }
}
