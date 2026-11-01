<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;

/**
 * What a sign-in proved before its session exists, carried through
 * establishment to the session's first proofs: the sign-in method, the first
 * factor's channel, observed properties, `amr` values and time, and the
 * provenance of a session established through an external provider.
 *
 * The session records them as it is written, pending or active, so the time the
 * credentials were verified carries to the active session unchanged; a further
 * factor a pending session waits for is recorded on it when it is given.
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
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  list<string>  $methods
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     */
    private function __construct(

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
        return new self($method, $factor->channel, $factor->observed, $factor->methods, $at->startOfSecond());
    }

    /**
     * The proof of a sign-in an external provider verified, under the named
     * method: the connection as its channel, the private external-provider
     * `amr` value, and the provider's authentication time, or now when it gave
     * none or one after now (the clocks disagree), with the provenance.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @param  \Carbon\CarbonImmutable  $now
     * @return self
     */
    public static function external(string $method, Provenance $provenance, CarbonImmutable $now): self
    {
        $now = $now->startOfSecond();
        $at  = $provenance->providerAuthenticatedAt;

        return new self(
            $method,
            new Channel(ChannelKind::EXTERNAL_PROVIDER, $provenance->connectionId),
            new ObservedProperties,
            [FirstFactor::EXTERNAL_PROVIDER_METHOD],
            $at === null || $at->greaterThan($now) ? $now : $at,
            $provenance,
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
        return new self($method, new Channel(ChannelKind::UNKNOWN), new ObservedProperties, [], $now->startOfSecond());
    }

    /**
     * The first factor as the session records it.
     *
     * @return \SineMacula\Laravel\Authentication\Proofs\NewProof
     */
    public function firstFactor(): NewProof
    {
        return new NewProof(ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, $this->method, $this->channel, null, $this->observed, null, $this->methods, $this->authenticatedAt);
    }
}
