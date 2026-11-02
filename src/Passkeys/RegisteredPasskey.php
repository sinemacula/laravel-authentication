<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;

/**
 * A passkey a registration verified, as the factor gate sees it before its row
 * is written: the id the row will have, its credential id as canonical unpadded
 * base64url (compared byte for byte), the relying party it was registered for,
 * what the registration's own authenticator data showed, and when.
 *
 * The observed properties are the registration's: user presence and
 * verification, backup eligibility and state as its flags reported them,
 * resistance to phishing (the origin and the relying party id were verified),
 * and no key protection, since the registration asks for no attestation.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RegisteredPasskey
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $credentialId
     * @param  string  $rpId
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  \Carbon\CarbonImmutable  $registeredAt
     */
    public function __construct(

        /** The passkey's id, as its row, its events and `remove()` carry it. */
        public string $id,

        /** The credential id, canonical unpadded base64url. */
        #[\SensitiveParameter] public string $credentialId,

        /** The relying party id it was registered for. */
        public string $rpId,

        /** What the registration's authenticator data showed. */
        public ObservedProperties $observed,

        /** When it was registered. */
        public CarbonImmutable $registeredAt,
    ) {}
}
