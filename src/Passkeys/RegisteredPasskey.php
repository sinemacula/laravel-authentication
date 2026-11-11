<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;

/**
 * A passkey a registration verified, as the factor gate sees it before its row
 * is written.
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
