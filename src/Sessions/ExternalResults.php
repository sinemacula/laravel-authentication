<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\External\EvidenceAcceptance;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalLink;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;

/**
 * What the external sign-in and reauthentication both ask of a verified result:
 * its link, and whether its evidence is accepted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalResults
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the result is handed to. */
        private GuardContext $context,

        /** Container the link contract is resolved from. */
        private Container $container,
    ) {}

    /**
     * The link the link contract finds for the result, or `null`, reported with
     * `ExternalResultUnlinked`.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalLink
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function link(ExternalResult $result, ClientContext $client): ?ExternalLink
    {
        $link = $this->container->make(ExternalIdentityLinks::class)->find($result->connectionId, $result->issuer, $result->subject, $result->nameIdFormat);

        if ($link === null) {
            $context = new EventContext($this->context->name(), $client, connectionId: $result->connectionId, requestReference: $result->requestReference);

            $this->context->dispatch(new ExternalResultUnlinked($context, $result->issuer));
        }

        return $link;
    }

    /**
     * Whether the link the link contract found is the one the result names,
     * byte for byte; a result that names none takes the contract's answer.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\External\ExternalLink  $link
     * @return bool
     */
    public static function isNamedLink(ExternalResult $result, ExternalLink $link): bool
    {
        return $result->linkId === null || $result->linkId === $link->id;
    }

    /**
     * The acceptance of the result's evidence for the identity and the evidence
     * as recorded, or neither when there is none or it is not accepted.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \SineMacula\Laravel\Authentication\Proofs\Evaluation, 1: \SineMacula\Laravel\Authentication\External\ExternalEvidence}|array{0: null, 1: null}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function acceptance(ExternalResult $result, Identity $identity, CarbonImmutable $now): array
    {
        if ($result->evidence === null) {
            return [null, null];
        }

        $subject    = new EvidenceSubject($identity, $this->context->name(), $result->connectionId, $now);
        $evaluation = EvidenceAcceptance::evaluate($result->evidence, $subject);

        return $evaluation === null ? [null, null] : [$evaluation, EvidenceAcceptance::asOf($result->evidence, $subject)];
    }
}
