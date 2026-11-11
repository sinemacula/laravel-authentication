<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;

/**
 * What was observed about the authenticator behind a proof; `null` means not
 * observed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ObservedProperties
{
    /**
     * Constructor.
     *
     * @param  ?bool  $userPresence
     * @param  ?bool  $userVerification
     * @param  ?bool  $backupEligible
     * @param  ?bool  $backupState
     * @param  ?bool  $phishingResistant
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection  $keyProtection
     */
    public function __construct(

        /** Whether the user was observed to be present. */
        public ?bool $userPresence = null,

        /** Whether the user was observed to be verified by the authenticator. */
        public ?bool $userVerification = null,

        /** Whether the credential was observed to be eligible for backup. */
        public ?bool $backupEligible = null,

        /** Whether the credential was observed to be backed up. */
        public ?bool $backupState = null,

        /** Whether the proof was observed to resist phishing (bound to the origin it was made for). */
        public ?bool $phishingResistant = null,

        /** How the key was observed to be protected. */
        public ?KeyProtection $keyProtection = null,
    ) {}
}
