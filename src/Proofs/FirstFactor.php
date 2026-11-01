<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * What a sign-in method verified: the identity, the channel it proved itself
 * over, what was observed about the authenticator, and the authentication
 * method reference values (`amr`) the proof stands for.
 *
 * The session service records it as the session's first-factor proof, timed
 * when the method returned it, and derives the access token's `amr` from its
 * values; the method decides acceptance, so this carries no evaluation. `mfa`
 * is reserved (see `AuthenticationMethods`) and refused here.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FirstFactor
{
    /** @var string The `amr` value of a sign-in through an external identity provider: a private, namespaced value (RFC 8176 names none for it). */
    public const string EXTERNAL_PROVIDER_METHOD = 'urn:sinemacula:amr:external_provider';

    /** @var list<string> The authentication method reference values the proof stands for. */
    public array $methods;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  array<array-key, mixed>  $methods
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity the method verified. */
        public Identity $identity,

        /** The channel the identity proved itself over. */
        public Channel $channel,

        /** What was observed about the authenticator; nothing, by default. */
        public ObservedProperties $observed = new ObservedProperties,

        // The authentication method reference values, `mfa` excluded.
        array $methods = [],
    ) {
        $this->methods = AuthenticationMethods::assertValid($methods);
    }
}
