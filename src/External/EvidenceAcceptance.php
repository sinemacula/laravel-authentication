<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;

/**
 * Decides whether an external provider's evidence is accepted at all, and so
 * whether it is recorded and counts: only when the bound
 * `ExternalEvidencePolicy` says it meets multifactor authentication, an
 * additional verification or phishing resistance, of any age. Anything else
 * (the default policy, evidence that meets none) is insufficient, and nothing
 * is recorded. A minimum assurance level has no level to ask for on its own, so
 * evidence that meets a level and none of the three is not accepted.
 *
 * The policy is asked first for multifactor authentication and, only when that
 * is not met, for an additional verification and then for phishing resistance,
 * stopping at the first it meets, each inside `WriteConnection::during()` for
 * the identity and for no tenant. Evidence dated after the time it is judged at
 * (the clocks disagree) is judged as of that time.
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
     * The evaluation of the evidence once accepted (accepted, and multifactor
     * when the policy says it meets multifactor authentication), or `null` when
     * it is insufficient.
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

        $meets = static fn (Requirement $requirement): bool => WriteConnection::during(
            $subject->identity,
            static fn (): bool => $policy->meets($evidence, $requirement, $subject),
        );

        if ($meets(new Requirement(multifactor: new RequirementPart))) {
            return new Evaluation(true, true);
        }

        return $meets(new Requirement(additionalVerification: new RequirementPart)) || $meets(new Requirement(phishingResistance: new RequirementPart))
            ? new Evaluation(true, false)
            : null;
    }

    /**
     * The evidence as it is judged at the subject's time: unchanged, unless it
     * is dated after that time, when it is dated then.
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
