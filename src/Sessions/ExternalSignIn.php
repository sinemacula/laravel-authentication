<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;

/**
 * Takes a result an external identity provider verified to the identity it is
 * linked to and the proof its session starts with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalSignIn
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\ExternalResults  $results
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation  $evaluation
     */
    public function __construct(

        /** Finds the result's link and judges its evidence. */
        private ExternalResults $results,

        /** Asks the application policy whether it allows external sign-in. */
        private PendingEvaluation $evaluation,
    ) {}

    /**
     * The identity the result is linked to and the proof its session starts
     * with, or the refusal.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Proofs\SignInProof}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function resolve(ExternalResult $result, SignInContext $context): array|Refused
    {
        if (!$this->evaluation->allowsMethod(SignInMethodManager::EXTERNAL_METHOD)) {
            return new Refused(FailureReason::METHOD_NOT_ALLOWED);
        }

        $link = $this->results->link($result, $context->client);

        if ($link === null || !ExternalResults::isNamedLink($result, $link)) {
            return new Refused($link === null ? FailureReason::EXTERNAL_RESULT_UNLINKED : FailureReason::LINK_MISMATCH);
        }

        $now = CarbonImmutable::now()->startOfSecond();

        [$evaluation, $evidence] = $this->results->acceptance($result, $link->identity, $now);

        $provenance = new Provenance(
            $result->connectionId,
            $result->tenantId,
            $result->authenticatedAt,
            $result->sessionNotAfter,
            $result->policyVersion,
            $link->id,
            $evidence,
            $result->providerContext,
        );

        return [$link->identity, SignInProof::external(SignInMethodManager::EXTERNAL_METHOD, $provenance, $now, $evaluation, $result->requestReference)];
    }
}
