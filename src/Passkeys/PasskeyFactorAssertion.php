<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;

/**
 * What a verified factor assertion showed, for the factor package to build its
 * proof from.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyFactorAssertion
{
    /**
     * Constructor.
     *
     * @param  string  $passkeyId
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  \Carbon\CarbonImmutable  $assertedAt
     * @param  \SineMacula\Laravel\Authentication\Passkeys\PasskeySummary  $passkey
     */
    public function __construct(

        /** The id of the passkey that asserted. */
        public string $passkeyId,

        /** Its credential id, canonical unpadded base64url. */
        #[\SensitiveParameter] public string $credentialId,

        /** What this assertion's authenticator data showed. */
        public ObservedProperties $observed,

        /** When it was verified. */
        public CarbonImmutable $assertedAt,

        /** The passkey, as its use left it. */
        public PasskeySummary $passkey,
    ) {}
}
