<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;

/**
 * What a sign-in proved before its session exists, carried through
 * establishment to the session's first proofs: the sign-in method, the first
 * factor's channel, observed properties, `amr` values and time, and the
 * provenance of a session established through an external provider, with the
 * acceptance of the provider's evidence when it was accepted.
 *
 * The session records them as it is written, pending or active, so the time the
 * credentials were verified carries to the active session unchanged; a further
 * factor a pending session waits for is recorded on it when it is given. The
 * first factor's id is chosen here, so a tenant policy judged against it in
 * memory at sign-in judges the very proof the session then records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInProof
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  list<string>  $methods
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Evaluation  $evaluation
     */
    private function __construct(

        /** The id the first factor is recorded under. */
        public string $id,

        /** The sign-in method that verified the first factor. */
        public string $method,

        /** The channel the first factor was proved over. */
        public Channel $channel,

        /** What was observed about the first factor's authenticator. */
        public ObservedProperties $observed,

        /** The first factor's authentication method reference values. */
        public array $methods,

        /** When the first factor was verified, to the whole second. */
        public CarbonImmutable $authenticatedAt,

        /** How a session established through an external provider began, if it was. */
        public ?Provenance $provenance = null,

        /** The acceptance of the provider's evidence, when it was accepted. */
        public ?Evaluation $evaluation = null,
    ) {}

    /**
     * The proof of a first factor the named sign-in method verified at the
     * given time.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\FirstFactor  $factor
     * @param  \Carbon\CarbonImmutable  $at
     * @return self
     */
    public static function verified(string $method, FirstFactor $factor, CarbonImmutable $at): self
    {
        return new self(self::newId(), $method, $factor->channel, $factor->observed, $factor->methods, $at->startOfSecond());
    }

    /**
     * The proof of a sign-in an external provider verified, under the named
     * method: the connection as its channel, the private external-provider
     * `amr` value, and the provider's authentication time, or now when it gave
     * none or one after now (the clocks disagree), with the provenance. The
     * first factor carries the evaluation `External\EvidenceAcceptance` gave
     * the provider's evidence when it was accepted, and the provenance carries
     * that evidence: the two come together or not at all.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Evaluation  $evaluation
     * @return self
     *
     * @throws \LogicException
     */
    public static function external(string $method, Provenance $provenance, CarbonImmutable $now, ?Evaluation $evaluation = null): self
    {
        if (($evaluation === null) !== ($provenance->evidence === null)) {
            throw new \LogicException('An external sign-in carries the acceptance of the provider\'s evidence and that evidence together, or neither.');
        }

        $now = $now->startOfSecond();
        $at  = $provenance->providerAuthenticatedAt;

        return new self(
            self::newId(),
            $method,
            new Channel(ChannelKind::EXTERNAL_PROVIDER, $provenance->connectionId),
            new ObservedProperties,
            [FirstFactor::EXTERNAL_PROVIDER_METHOD],
            $at === null || $at->greaterThan($now) ? $now : $at,
            $provenance,
            $evaluation,
        );
    }

    /**
     * The proof of a sign-in something outside the guard verified under the
     * named method and did not describe: an unknown channel, no `amr` values,
     * verified now.
     *
     * @param  string  $method
     * @param  \Carbon\CarbonImmutable  $now
     * @return self
     */
    public static function unattested(string $method, CarbonImmutable $now): self
    {
        return new self(self::newId(), $method, new Channel(ChannelKind::UNKNOWN), new ObservedProperties, [], $now->startOfSecond());
    }

    /**
     * The first factor as the session records it.
     *
     * @return \SineMacula\Laravel\Authentication\Proofs\NewProof
     */
    public function firstFactor(): NewProof
    {
        return new NewProof(
            ProofKind::FIRST_FACTOR,
            Purpose::SIGN_IN,
            $this->method,
            $this->channel,
            null,
            $this->observed,
            $this->evaluation,
            $this->methods,
            $this->authenticatedAt,
            $this->provenance?->evidence,
        );
    }

    /**
     * The first factor as it reads back once recorded, under its id.
     *
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    public function recorded(): RecordedProof
    {
        $factor = $this->firstFactor();

        return new RecordedProof(
            $this->id,
            $factor->kind,
            $factor->purpose,
            $factor->method,
            $factor->channel,
            null,
            $factor->observed,
            $factor->evaluation,
            $factor->methods,
            $factor->authenticatedAt,
            $factor->evidence,
        );
    }

    /**
     * A new proof id, time-ordered like the ones `ProofWriter` chooses.
     *
     * @return string
     */
    private static function newId(): string
    {
        return Str::uuid7()->toString();
    }
}
