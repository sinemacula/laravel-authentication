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
 * What the external sign-in and the external reauthentication both ask of a
 * result an external identity provider verified: the link the link contract
 * finds for its connection, issuer and subject (reporting one linked to no
 * identity with `ExternalResultUnlinked`), and whether the evidence it carries
 * is accepted, and so recorded and counted, for the identity it is linked to.
 *
 * Neither locks or writes anything: both are asked before any lock the package
 * takes, so the adapter's own locks, taken inside its transaction, come first.
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
     * The link the link contract finds for the result, or `null`, reporting a
     * result linked to no identity with `ExternalResultUnlinked` from the
     * client given.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalLink
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function link(ExternalResult $result, ClientContext $client): ?ExternalLink
    {
        $link = $this->container->make(ExternalIdentityLinks::class)->find($result->connectionId, $result->issuer, $result->subject);

        if ($link === null) {
            $this->context->dispatch(new ExternalResultUnlinked(new EventContext($this->context->name(), $client), $result->connectionId, $result->issuer));
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
     * The acceptance of the result's evidence for the identity, as the evidence
     * contract judges it at the time given, and the evidence as it is recorded
     * (dated no later than then), or neither: a result without evidence, or
     * with evidence the contract does not accept, has nothing recorded or
     * counted.
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
