<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\External\ExternalLink;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;

/**
 * Takes a result an external identity provider verified to the identity it is
 * linked to and the proof its session starts with, before the session service
 * starts that session as it starts any other.
 *
 * In order: the application policy must allow `external_provider`
 * (`method_not_allowed`), so an application that does not allow external
 * sign-in never has the link contract asked; then the link contract must link
 * the connection, issuer and subject to an identity. A result it links to none
 * dispatches `ExternalResultUnlinked` and is refused as
 * `external_result_unlinked`. A linked one is the link's identity and the
 * provider's proof: the connection as its channel, the private
 * external-provider `amr` value and the provider's time (see
 * `SignInProof::external()`), with the provenance the session records, the
 * link's id included.
 *
 * Nothing here locks or writes: the link contract is asked before any lock the
 * sign-in takes, so the adapter's own locks, taken inside its transaction, come
 * before the session's.
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
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation  $evaluation
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the result is handed to. */
        private GuardContext $context,

        /** Asks the application policy whether it allows external sign-in. */
        private PendingEvaluation $evaluation,

        /** Container the link contract is resolved from. */
        private Container $container,
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
     */
    public function resolve(ExternalResult $result, SignInContext $context): array|Refused
    {
        if (!$this->evaluation->allowsMethod(SignInMethodManager::EXTERNAL_METHOD)) {
            return new Refused(FailureReason::METHOD_NOT_ALLOWED);
        }

        $link = $this->link($result, $context);

        if ($link === null) {
            return new Refused(FailureReason::EXTERNAL_RESULT_UNLINKED);
        }

        $provenance = new Provenance(
            $result->connectionId,
            $result->tenantId,
            $result->authenticatedAt,
            $result->sessionNotAfter,
            $result->policyVersion,
            $link->id,
        );

        return [$link->identity, SignInProof::external(SignInMethodManager::EXTERNAL_METHOD, $provenance, CarbonImmutable::now())];
    }

    /**
     * The link the link contract finds for the result, or `null`, reporting a
     * result linked to no identity with `ExternalResultUnlinked`.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalLink
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function link(ExternalResult $result, SignInContext $context): ?ExternalLink
    {
        $link = $this->container->make(ExternalIdentityLinks::class)->find($result->connectionId, $result->issuer, $result->subject);

        if ($link === null) {
            $this->context->dispatch(new ExternalResultUnlinked(new EventContext($this->context->name(), $context->client), $result->connectionId, $result->issuer));
        }

        return $link;
    }
}
